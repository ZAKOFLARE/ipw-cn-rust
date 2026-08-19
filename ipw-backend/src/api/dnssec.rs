//! /v1/dnssec/:domain DNSSEC 验证（对齐 Go dnssecHandler，无缓存）

use super::{AppState, error_json, ok_json};
use crate::webtest::dnssec::resolve_dnssec;
use axum::extract::{Path, State};
use std::sync::Arc;

/// DNSSEC handler（对齐 dnssecHandler）
pub async fn dnssec_handler(
    State(state): State<Arc<AppState>>,
    Path(domain): Path<String>,
) -> axum::response::Response {
    if domain.is_empty() {
        return error_json(400, "Domain parameter is required");
    }

    let result = resolve_dnssec(&domain, &state.dns).await;
    ok_json(&result)
}
