//! /v1/whois/:domain Whois 查询（对齐 Go whoisHandler）

use super::{AppState, error_json, ok_json};
use crate::webtest::whois::query_whois;
use axum::extract::{Path, State};
use std::sync::Arc;

/// Whois handler（对齐 whoisHandler）
pub async fn whois_handler(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    if domain.is_empty() {
        return error_json(400, "Domain parameter is required");
    }

    if let Some(cached) = state.whois_cache.get(&domain) {
        return ok_json(&cached);
    }

    // 对齐 Go：QueryWhois 恒返回 result（错误在 result.Error 字段），handler 永不 500
    let result = query_whois(&domain, &state.dns).await;
    state.whois_cache.insert(domain, result.clone());
    ok_json(&result)
}
