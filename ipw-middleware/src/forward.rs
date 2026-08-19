//! 中间层转发逻辑（对齐 Go 原版 middleware-go/main.go 的 middlewareHandler）
//!
//! 路径格式：/{prefix}/{backendID}/{apiType}/{raw...}，prefix ∈ {v1, middleware}
//! apiType：whois / dns / location / ssl / asn / dnssec / detail / tcping / speed

use crate::config::{ApiInfo, MiddlewareConfig, StackConfig};
use axum::extract::{Path, Query, Request, State};
use axum::http::StatusCode;
use axum::response::Response;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// 转发错误响应（对齐 Go badRequest）
fn bad_request(msg: &str) -> Response {
    json_response(StatusCode::BAD_REQUEST, msg, "statusCode", "statusMessage")
}

/// 502 响应（对齐 Go forwardUpstream 的网络错误分支）
fn bad_gateway(msg: &str) -> Response {
    json_response(StatusCode::BAD_GATEWAY, msg, "statusCode", "statusMessage")
}

fn json_response(
    status: StatusCode,
    msg: &str,
    status_key: &str,
    message_key: &str,
) -> Response {
    let body = format!(
        r#"{{"{}":{},"{}":"{}"}}"#,
        status_key,
        status.as_u16(),
        message_key,
        msg.replace('"', "\\\"")
    );
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(body))
        .unwrap()
}

/// 透传上游状态码与 body（对齐 Go forwardUpstream）
fn passthrough(status: u16, body: Vec<u8>) -> Response {
    let mut resp = Response::new(axum::body::Body::from(body));
    *resp.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_GATEWAY);
    resp.headers_mut().insert("content-type", "application/json".parse().unwrap());
    resp
}

/// 从节点列表按 id 查找 URL（对齐 Go findURL）
fn find_url(list: &[ApiInfo], id: &str) -> Option<String> {
    list.iter().find(|api| api.id == id).map(|api| api.url.clone())
}

/// 收集 tcping/speed 的所有分栈节点（对齐 Go：DualStack + IPv4 + IPv6 合并）
fn collect_stack_nodes(stack: &StackConfig) -> Vec<ApiInfo> {
    let mut out = Vec::new();
    out.extend(stack.dual_stack.iter().cloned());
    out.extend(stack.ipv4.iter().cloned());
    out.extend(stack.ipv6.iter().cloned());
    out
}

/// 路由 handler（对齐 Go middlewareHandler）
pub async fn middleware_handler(
    State(config): State<Arc<MiddlewareConfig>>,
    Path(slug): Path<String>,
    Query(query): Query<HashMap<String, String>>,
    req: Request,
) -> Response {
    // 对齐 Go：手动 URL 解码（fiber 默认不解码路径参数）
    let decoded = match percent_encoding::percent_decode_str(&slug).decode_utf8() {
        Ok(d) => d.to_string(),
        Err(_) => return bad_request("Missing slug parameter"),
    };
    if decoded.is_empty() {
        return bad_request("Missing slug parameter");
    }

    // Go 语义：slug 是可变字符串数组 []string
    let mut parts: Vec<String> = decoded.split('/').map(|s| s.to_string()).collect();

    // 如果分段超过 4 个，raw 部分包含协议（如 https://example.com），重新拼回（对齐 Go）
    if parts.len() > 4 {
        let backend_id = &parts[0];
        let api_type = &parts[1];
        let protocol = &parts[2];
        let rest = parts[3..].join("/");
        if protocol == "https:" || protocol == "http:" {
            parts = vec![backend_id.clone(), api_type.clone(), format!("{protocol}//{rest}")];
        } else {
            return bad_request("Invalid slug");
        }
    }

    if parts.len() < 3 {
        return bad_request("Missing parameters in slug");
    }
    let backend_id = &parts[0];
    let api_type = &parts[1];
    let raw = parts[2..].join("/");
    if backend_id.is_empty() || api_type.is_empty() || raw.is_empty() {
        return bad_request("Missing parameters in slug");
    }

    // API key：apiKeys[backendID] → Authorization: Bearer
    let api_key = config.api_keys.get(backend_id).cloned().unwrap_or_default();

    // 选择节点表
    let api_base_urls: Vec<ApiInfo> = match api_type.as_str() {
        "whois" | "ssl" | "detail" => config.api_base_urls.clone(),
        "dns" | "dnssec" => config.ns_lookup.clone(),
        "location" | "asn" => config.ip_location_apis.clone(),
        "tcping" => collect_stack_nodes(&config.tcping),
        "speed" => collect_stack_nodes(&config.speed_test),
        _ => return bad_request("Invalid API type"),
    };

    let api_base_url = match find_url(&api_base_urls, backend_id) {
        Some(u) => u,
        None => return bad_request("Invalid backend ID"),
    };
    let base = if api_base_url.ends_with('/') { api_base_url } else { format!("{api_base_url}/") };

    // 构造上游请求（对齐 Go forwardUpstream + authHeaders）
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(config.http_timeout_seconds.max(1)))
        .build()
        .expect("build upstream client");

    let target = format!("{base}v1/{api_type}/{raw}");

    let mut req_builder = client.get(&target);
    // Origin 透传（有则带，对齐 Go）
    if let Some(origin) = req.headers().get("origin").and_then(|v| v.to_str().ok()) {
        req_builder = req_builder.header("Origin", origin);
    }
    if !api_key.is_empty() {
        req_builder = req_builder.bearer_auth(&api_key);
    }

    // 转发 query（过滤空值，对齐 Go）
    let non_empty_query: HashMap<String, String> = query
        .into_iter()
        .filter(|(_, v)| !v.is_empty())
        .collect();
    req_builder = req_builder.query(&non_empty_query);

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let body = resp.bytes().await.unwrap_or_default().to_vec();
            passthrough(status, body)
        }
        Err(e) => {
            tracing::warn!(target = %target, error = %e, "upstream unreachable");
            bad_gateway("Backend unreachable")
        }
    }
}
