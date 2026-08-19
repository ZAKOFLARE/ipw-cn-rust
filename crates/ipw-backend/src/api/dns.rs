//! /v1/dns/:type/*domain DNS 解析（对齐 Go dnsQueryHandler）

use super::{AppState, error_json, normalize_url, ok_json};
use crate::webtest::dns;
use axum::extract::{Path, State};
use std::sync::Arc;

/// DNS handler（对齐 dnsQueryHandler）
pub async fn dns_handler(
    State(state): State<Arc<AppState>>,
    Path((rtype, domain_raw)): Path<(String, String)>,
) -> axum::response::Response {
    // 对齐 Go：parseURL(domain) 取 Host
    let parsed = match url::Url::parse(&normalize_url(&domain_raw)) {
        Ok(p) => p,
        Err(_) => return error_json(400, "Invalid domain"),
    };
    let domain = match parsed.host_str() {
        Some(h) => h.to_string(),
        None => return error_json(400, "Invalid domain"),
    };
    if domain.is_empty() {
        return error_json(400, "Invalid domain");
    }

    let dns_cfg = &state.dns;
    let rtype = rtype.to_lowercase();

    macro_rules! resolve_case {
        ($result_fn:ident) => {
            match dns::$result_fn(&domain, dns_cfg).await {
                Ok(result) => return ok_json(&result),
                Err(e) => return error_json(500, &e),
            }
        };
    }

    match rtype.as_str() {
        "a" => resolve_case!(resolve_a_result),
        "aaaa" => resolve_case!(resolve_aaaa_result),
        "cname" => resolve_case!(resolve_cname_result),
        "mx" => resolve_case!(resolve_mx_result),
        "ns" => resolve_case!(resolve_ns_result),
        "ptr" => resolve_case!(resolve_ptr_result),
        "srv" => resolve_case!(resolve_srv_result),
        "txt" => resolve_case!(resolve_txt_result),
        "caa" => resolve_case!(resolve_caa_result),
        _ => error_json(400, "Invalid record type"),
    }
}
