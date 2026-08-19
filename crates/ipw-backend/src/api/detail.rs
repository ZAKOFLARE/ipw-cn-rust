//! /v1/detail/*url 网站检测（对齐 Go checkWebsiteHandler + checkWebsite）

use super::timing::{clean_host_record, download_speed, measure_connection};
use super::types::{WebsiteCheckDetail, WebsiteCheckResult};
use super::{AppState, error_json, normalize_url, ok_json, ssrf_pretest};
use crate::config::SingleStack;
use axum::extract::{Path, State};
use futures::StreamExt;
use std::sync::Arc;

/// 网站检测 handler（对齐 checkWebsiteHandler）
pub async fn detail_handler(
    State(state): State<Arc<AppState>>,
    Path(url): Path<String>,
) -> axum::response::Response {
    if url.is_empty() {
        return error_json(400, "URL parameter is required");
    }

    let test_url = normalize_url(&url);

    // SSRF 预检：命中私有地址返回蜜罐响应（对齐 Go HasLocalOrPrivateIP 分支，传完整 URL 保留路径）
    match ssrf_pretest(&test_url, &state.setting.dns_server).await {
        Ok(_) => {}
        Err(_) => {
            return ok_json(&WebsiteCheckResult {
                ipv4: Some(WebsiteCheckDetail::fake_perfect(&test_url)),
                ipv6: Some(WebsiteCheckDetail::fake_perfect(&test_url)),
            });
        }
    }

    // 缓存命中（TTL 内）
    if let Some(cached) = state.website_cache.get(&test_url) {
        return ok_json(&cached);
    }

    // 单飞：并发同 key 请求共享执行
    let state_clone = state.clone();
    let url_for_sf = test_url.clone();
    let result = state
        .website_sf
        .run(&test_url, async move {
            check_website_result(&state_clone, &url_for_sf).await
        })
        .await;

    match result {
        Ok(result) => ok_json(&result),
        Err(e) => error_json(400, &e),
    }
}

/// 双栈检测（对齐 checkWebsiteHandler 的 SINGLE_STACK 分支逻辑）
async fn check_website_result(state: &AppState, url: &str) -> Result<WebsiteCheckResult, String> {
    let mut result = WebsiteCheckResult {
        ipv4: None,
        ipv6: None,
    };

    match state.setting.single_stack {
        SingleStack::Ipv4 => {
            let ipv4 = match check_website(state, url, "v4").await {
                Ok(d) => d,
                Err(e) => WebsiteCheckDetail::error(&e),
            };
            result.ipv4 = Some(ipv4);
            result.ipv6 = Some(WebsiteCheckDetail::skipped("Skipped due to SINGLE_STACK=ipv4"));
        }
        SingleStack::Ipv6 => {
            let ipv6 = match check_website(state, url, "v6").await {
                Ok(d) => d,
                Err(e) => WebsiteCheckDetail::error(&e),
            };
            result.ipv6 = Some(ipv6);
            result.ipv4 = Some(WebsiteCheckDetail::skipped("Skipped due to SINGLE_STACK=ipv6"));
        }
        SingleStack::Dual => {
            let (ipv6, ipv4) = tokio::join!(
                check_website(state, url, "v6"),
                check_website(state, url, "v4")
            );
            result.ipv6 = Some(match ipv6 {
                Ok(d) => d,
                Err(e) => WebsiteCheckDetail::error(&e),
            });
            result.ipv4 = Some(match ipv4 {
                Ok(d) => d,
                Err(e) => WebsiteCheckDetail::error(&e),
            });
        }
    }

    // 对齐 Go：结果入缓存（成功 5min / 失败 30s 由 FailureAware 决定）
    state.website_cache.insert(url.to_string(), result.clone());

    Ok(result)
}

/// 单栈网站检测（对齐 checkWebsite）
async fn check_website(state: &AppState, url: &str, version: &str) -> Result<WebsiteCheckDetail, String> {
    let client = state.http.pick(version);
    let v6 = version == "v6";

    // 连接测量（DNS + TCP + TLS 计时），失败不影响主请求
    let parsed = url::Url::parse(url).map_err(|e| e.to_string())?;
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let timing = measure_connection(&host, port, v6, &state.dns, &state.tls).await;

    // 主请求（HTTPS 失败回退 HTTP，对齐 Go）
    let start = std::time::Instant::now();
    let mut fallback_to_http = false;
    let resp = match client.get(url).send().await {
        Ok(r) => r,
        Err(e) => {
            if url.starts_with("https://") {
                let http_url = url.replacen("https://", "http://", 1);
                match client.get(&http_url).send().await {
                    Ok(r) => {
                        fallback_to_http = true;
                        r
                    }
                    Err(e2) => return Err(e2.to_string()),
                }
            } else {
                return Err(e.to_string());
            }
        }
    };

    let http_status = resp.status().as_u16() as i64;
    let https_status = if fallback_to_http { 0 } else { http_status };

    // 流式读取：首个 chunk 到达时记录 first_byte_time（对齐 Go trace.ServerTime）
    let mut body: Vec<u8> = Vec::new();
    let mut first_byte_ms = 0.0f64;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| e.to_string())?;
        if first_byte_ms == 0.0 {
            first_byte_ms = start.elapsed().as_secs_f64() * 1000.0;
        }
        body.extend_from_slice(&chunk);
    }
    let total_ms = start.elapsed().as_millis() as f64;

    let host_record = clean_host_record(&timing.resolved_ip);

    let dns_lookup_time = timing.dns_lookup_ms;
    let tcp_connect_time = timing.tcp_connect_ms;
    let http_connect_time = timing.http_connect_ms;
    let first_byte_time = first_byte_ms;

    let page_size = body.len() as i64;
    let download_speed = download_speed(body.len(), total_ms);

    Ok(WebsiteCheckDetail {
        host_record,
        http_status_code: http_status,
        https_status_code: https_status,
        dns_lookup_time,
        tcp_connect_time,
        http_connect_time,
        first_byte_time,
        total_time: total_ms,
        page_size,
        download_speed,
        is_reachable: true,
    })
}
