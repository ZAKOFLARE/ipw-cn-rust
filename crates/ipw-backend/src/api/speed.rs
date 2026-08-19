//! /v1/speed/:version/*url 网站测速（对齐 Go websiteSpeedTestHandler + websiteSpeed）

use super::timing::{clean_host_record, download_speed, measure_connection};
use super::types::WebsiteSpeedTestResult;
use super::{AppState, error_json, normalize_url, ok_json, ssrf_pretest, status_json};
use crate::config::SingleStack;
use axum::extract::{Path, State};
use futures::StreamExt;
use std::sync::Arc;

/// 测速 handler（对齐 websiteSpeedTestHandler）
pub async fn speed_handler(
    State(state): State<Arc<AppState>>,
    Path((version, url)): Path<(String, String)>,
) -> axum::response::Response {
    if url.is_empty() {
        return error_json(400, "URL parameter is required");
    }
    let test_url = normalize_url(&url);

    // version 校验（对齐 Go：非 v4/v6 返回 400 "Invalid version"）
    if version != "v4" && version != "v6" {
        return error_json(400, "Invalid version");
    }

    // SINGLE_STACK 与请求版本匹配检查（对齐 Go：不匹配返回 400 + skipped 对象体）
    match state.setting.single_stack {
        SingleStack::Ipv4 if version != "v4" => {
            return status_json(400, &WebsiteSpeedTestResult {
                version: "v4".to_string(),
                host_record: "Skipped due to SINGLE_STACK=ipv4".to_string(),
                ..Default::default()
            });
        }
        SingleStack::Ipv6 if version != "v6" => {
            return status_json(400, &WebsiteSpeedTestResult {
                version: "v6".to_string(),
                host_record: "Skipped due to SINGLE_STACK=ipv6".to_string(),
                ..Default::default()
            });
        }
        _ => {}
    }

    let cache_key = format!("{test_url}:{version}");

    if let Some(cached) = state.speed_cache.get(&cache_key) {
        return ok_json(&cached);
    }

    let state_clone = state.clone();
    let url_for_sf = test_url.clone();
    let ver_for_sf = version.clone();
    let result = state
        .speed_sf
        .run(&cache_key, async move {
            let r = website_speed(&state_clone, &url_for_sf, &ver_for_sf).await;
            // 对齐 Go：错误结果也入缓存（30s 由 FailureAware 决定）
            state_clone
                .speed_cache
                .insert(format!("{url_for_sf}:{ver_for_sf}"), r.clone());
            Ok::<_, String>(r)
        })
        .await;

    match result {
        Ok(r) => ok_json(&r),
        Err(e) => error_json(400, &e),
    }
}

/// 单栈测速（对齐 websiteSpeed）
async fn website_speed(state: &AppState, url: &str, version: &str) -> WebsiteSpeedTestResult {
    // SSRF 预检
    if let Err(e) = ssrf_pretest(url, &state.setting.dns_server).await {
        return WebsiteSpeedTestResult {
            host_record: format!("Error: {e}"),
            ..Default::default()
        };
    }

    let client = state.http.pick(version);
    let v6 = version == "v6";

    let parsed = match url::Url::parse(url) {
        Ok(p) => p,
        Err(e) => {
            return WebsiteSpeedTestResult {
                host_record: format!("Error: {e}"),
                ..Default::default()
            };
        }
    };
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port_or_known_default().unwrap_or(80);
    let timing = measure_connection(&host, port, v6, &state.dns, &state.tls).await;

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
                    Err(e2) => {
                        return WebsiteSpeedTestResult {
                            host_record: format!("Error: {e2}"),
                            ..Default::default()
                        };
                    }
                }
            } else {
                return WebsiteSpeedTestResult {
                    host_record: format!("Error: {e}"),
                    ..Default::default()
                };
            }
        }
    };

    let http_status = resp.status().as_u16() as i64;
    let https_status = if fallback_to_http { 0 } else { http_status };
    let headers = dump_response_headers(&resp);

    // 流式读取：首个 chunk 到达时记录 first_byte_time（对齐 Go trace.ServerTime）
    let mut body: Vec<u8> = Vec::new();
    let mut first_byte_ms = 0.0f64;
    let mut stream = resp.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(c) => c,
            Err(e) => {
                return WebsiteSpeedTestResult {
                    host_record: format!("Error: {e}"),
                    ..Default::default()
                };
            }
        };
        if first_byte_ms == 0.0 {
            first_byte_ms = start.elapsed().as_secs_f64() * 1000.0;
        }
        body.extend_from_slice(&chunk);
    }
    let total_ms = start.elapsed().as_millis() as f64;

    WebsiteSpeedTestResult {
        version: version.to_string(),
        headers,
        host_record: clean_host_record(&timing.resolved_ip),
        http_status_code: http_status,
        https_status_code: https_status,
        dns_lookup_time: timing.dns_lookup_ms,
        tcp_connect_time: timing.tcp_connect_ms,
        http_connect_time: timing.http_connect_ms,
        first_byte_time: first_byte_ms,
        total_time: total_ms,
        page_size: body.len() as i64,
        download_speed: download_speed(body.len(), total_ms),
        message: String::new(),
        is_reachable: true,
    }
}

/// 响应头转 DumpResponse 格式（对齐 Go httputil.DumpResponse(resp, false)）
fn dump_response_headers(resp: &reqwest::Response) -> String {
    let mut out = String::new();
    let status = resp.status();
    let reason = status
        .canonical_reason()
        .unwrap_or("");
    out.push_str(&format!(
        "HTTP/{} {} {}\r\n",
        version_label(resp.version()),
        status.as_u16(),
        reason
    ));
    for (k, v) in resp.headers() {
        if let Ok(vs) = v.to_str() {
            out.push_str(&format!("{}: {}\r\n", k, vs));
        }
    }
    out.push_str("\r\n");
    out
}

fn version_label(v: reqwest::Version) -> &'static str {
    match v {
        reqwest::Version::HTTP_09 => "0.9",
        reqwest::Version::HTTP_10 => "1.0",
        reqwest::Version::HTTP_11 => "1.1",
        reqwest::Version::HTTP_2 => "2.0",
        reqwest::Version::HTTP_3 => "3.0",
        _ => "1.1",
    }
}

// 供 Default derive 使用
impl Default for WebsiteSpeedTestResult {
    fn default() -> Self {
        Self {
            version: String::new(),
            host_record: String::new(),
            http_status_code: 0,
            https_status_code: 0,
            dns_lookup_time: 0.0,
            tcp_connect_time: 0.0,
            http_connect_time: 0.0,
            first_byte_time: 0.0,
            total_time: 0.0,
            page_size: 0,
            download_speed: 0.0,
            message: String::new(),
            headers: String::new(),
            is_reachable: false,
        }
    }
}
