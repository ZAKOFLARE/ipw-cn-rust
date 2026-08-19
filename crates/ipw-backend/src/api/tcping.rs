//! /v1/tcping/:ip TCP 连接测试（对齐 Go pingHandler）

use super::types::TcpPingResult;
use super::{AppState, error_json, ok_json};
use crate::config::SingleStack;
use crate::webtest::tcping::{TcpPingStats, tcping_run};
use axum::extract::{Path, Query, State};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Deserialize)]
pub struct PingQuery {
    port: Option<String>,
    count: Option<String>,
}

/// TCPing handler（对齐 pingHandler）
pub async fn ping_handler(
    State(state): State<Arc<AppState>>,
    Path(host): Path<String>,
    Query(query): Query<PingQuery>,
) -> axum::response::Response {
    if host.is_empty() {
        return error_json(400, "IP or hostname parameter is required");
    }

    let port = query.port.clone().unwrap_or_else(|| "80".to_string());
    match port.parse::<u16>() {
        Ok(1..=65535) => {}
        _ => return error_json(400, "Invalid port number"),
    }

    let count = match query.count.clone() {
        Some(s) => match s.parse::<i64>() {
            Ok(n) if (1..=20).contains(&n) => n,
            _ => return error_json(400, "count must be an integer between 1 and 20"),
        },
        None => 4,
    };

    let cache_key = format!("{host}:{port}:{count}");
    if let Some(cached) = state.ping_cache.get(&cache_key) {
        return ok_json(&cached);
    }

    let state_clone = state.clone();
    let host_for_sf = host.clone();
    let port_for_sf = port.clone();
    let result = state
        .ping_sf
        .run(&cache_key, async move {
            ping_result(&state_clone, &host_for_sf, &port_for_sf, count).await
        })
        .await;

    match result {
        Ok(result) => ok_json(&result),
        Err(e) => error_json(400, &e),
    }
}

/// 双栈 ping（对齐 pingHandler 的 SINGLE_STACK 分支）
async fn ping_result(
    state: &AppState,
    host: &str,
    port: &str,
    count: i64,
) -> Result<TcpPingResult, String> {
    let dns = &state.dns;
    let timeout = Duration::from_secs(10);
    let interval = Duration::from_millis(100);

    let mut result = TcpPingResult { ipv4: None, ipv6: None };

    match state.setting.single_stack {
        SingleStack::Ipv4 => {
            result.ipv4 = Some(run_stack(state, host, port, count, "v4", timeout, interval, dns).await);
            result.ipv6 = Some(skipped_stats("Skipped due to SINGLE_STACK=ipv4"));
        }
        SingleStack::Ipv6 => {
            result.ipv6 = Some(run_stack(state, host, port, count, "v6", timeout, interval, dns).await);
            result.ipv4 = Some(skipped_stats("Skipped due to SINGLE_STACK=ipv6"));
        }
        SingleStack::Dual => {
            let (ipv6, ipv4) = tokio::join!(
                run_stack(state, host, port, count, "v6", timeout, interval, dns),
                run_stack(state, host, port, count, "v4", timeout, interval, dns)
            );
            result.ipv6 = Some(ipv6);
            result.ipv4 = Some(ipv4);
        }
    }

    state.ping_cache.insert(format!("{host}:{port}:{count}"), result.clone());
    Ok(result)
}

async fn run_stack(
    _state: &AppState,
    host: &str,
    port: &str,
    count: i64,
    version: &str,
    timeout: Duration,
    interval: Duration,
    dns: &crate::webtest::dns::DnsConfig,
) -> TcpPingStats {
    match tcping_run(host, port, count, version, timeout, interval, dns).await {
        Ok(stats) => stats,
        Err(e) => TcpPingStats {
            ip: format!("Error: {e}"),
            ..Default::default()
        },
    }
}

fn skipped_stats(msg: &str) -> TcpPingStats {
    TcpPingStats {
        ip: msg.to_string(),
        ..Default::default()
    }
}

// 供测试使用
#[allow(dead_code)]
fn _query_map(q: &HashMap<String, String>) -> String {
    format!("{}", q.len())
}
