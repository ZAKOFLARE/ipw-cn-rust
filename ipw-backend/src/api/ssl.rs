//! /v1/ssl/*url SSL 证书检查（对齐 Go sslCheckHandler + checkSSL）
//!
//! 证书通过独立 TLS 握手获取（reqwest 不暴露 peer certificates）；
//! 主请求用于状态码 / HTTP 版本 / 耗时。

use super::timing::{clean_host_record, download_speed};
use super::types::{SslCheckDetail, SslCheckResult};
use super::{AppState, error_json, normalize_url, ok_json, ssrf_pretest};
use crate::config::SingleStack;
use axum::extract::{Path, State};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use x509_parser::prelude::*;

/// SSL 检查 handler（对齐 sslCheckHandler）
pub async fn ssl_handler(
    State(state): State<Arc<AppState>>,
    Path(url): Path<String>,
) -> axum::response::Response {
    if url.is_empty() {
        return error_json(400, "URL parameter is required");
    }

    let test_url = normalize_url(&url);

    // SSRF 预检：命中私有地址返回无效证书蜜罐（对齐 Go）
    match ssrf_pretest(&test_url, &state.setting.dns_server).await {
        Ok(_) => {}
        Err(_) => {
            let host = super::parse_host(&test_url);
            return ok_json(&SslCheckResult {
                ipv4: Some(SslCheckDetail::fake_invalid(&host)),
                ipv6: Some(SslCheckDetail::fake_invalid(&host)),
            });
        }
    }

    if let Some(cached) = state.ssl_cache.get(&test_url) {
        return ok_json(&cached);
    }

    let state_clone = state.clone();
    let url_for_sf = test_url.clone();
    let result = state
        .ssl_sf
        .run(&test_url, async move { check_ssl_result(&state_clone, &url_for_sf).await })
        .await;

    match result {
        Ok(result) => ok_json(&result),
        Err(e) => error_json(400, &e),
    }
}

/// 双栈 SSL 检查（对齐 sslCheckHandler 的 SINGLE_STACK 分支）
async fn check_ssl_result(state: &AppState, url: &str) -> Result<SslCheckResult, String> {
    let mut result = SslCheckResult { ipv4: None, ipv6: None };

    match state.setting.single_stack {
        SingleStack::Ipv4 => {
            result.ipv4 = Some(match check_ssl(state, url, "v4").await {
                Ok(d) => d,
                Err(e) => SslCheckDetail::error(&e),
            });
            result.ipv6 = Some(SslCheckDetail::skipped("Skipped due to SINGLE_STACK=ipv4"));
        }
        SingleStack::Ipv6 => {
            result.ipv6 = Some(match check_ssl(state, url, "v6").await {
                Ok(d) => d,
                Err(e) => SslCheckDetail::error(&e),
            });
            result.ipv4 = Some(SslCheckDetail::skipped("Skipped due to SINGLE_STACK=ipv6"));
        }
        SingleStack::Dual => {
            let (ipv6, ipv4) = tokio::join!(check_ssl(state, url, "v6"), check_ssl(state, url, "v4"));
            result.ipv6 = Some(match ipv6 {
                Ok(d) => d,
                Err(e) => SslCheckDetail::error(&e),
            });
            result.ipv4 = Some(match ipv4 {
                Ok(d) => d,
                Err(e) => SslCheckDetail::error(&e),
            });
        }
    }

    state.ssl_cache.insert(url.to_string(), result.clone());
    Ok(result)
}

/// 单栈 SSL 检查（对齐 checkSSL）
async fn check_ssl(state: &AppState, url: &str, version: &str) -> Result<SslCheckDetail, String> {
    let client = state.http.pick(version);
    let v6 = version == "v6";

    let parsed = url::Url::parse(url).map_err(|e| e.to_string())?;
    let host = parsed.host_str().unwrap_or("").to_string();
    let port = parsed.port_or_known_default().unwrap_or(443);

    // 独立 TLS 握手获取证书（Go 的 SSLCheckDetail 无 tcp/http 连接时间字段）
    let tls = &state.tls;
    let mut resolved_ip = String::new();
    let mut peer_certs: Option<Vec<rustls::pki_types::CertificateDer<'static>>> = None;

    let ips = crate::http::resolve_host(&host, v6, &state.dns).await.unwrap_or_default();
    if let Some(ip) = ips.first() {
        resolved_ip = ip.to_string();
        let addr = std::net::SocketAddr::new(*ip, port);
        // 连接与 TLS 握手超时 10s（对齐 Go dialer Timeout: 10s）
        let connect = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(addr),
        )
        .await;
        if let Ok(Ok(stream)) = connect {
            if let Ok(name) = rustls::pki_types::ServerName::try_from(host.clone()) {
                let tls_connect = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tls.connect(name, stream),
                )
                .await;
                if let Ok(Ok(tls_stream)) = tls_connect {
                    let (_, conn) = tls_stream.get_ref();
                    peer_certs = conn.peer_certificates().map(|c| c.to_vec());
                }
            }
        }
    }

    // 主请求
    let start = std::time::Instant::now();
    let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
    let http_version = http_version_str(resp.version());
    let https_status = resp.status().as_u16() as i64;
    let body = resp.bytes().await.map_err(|e| e.to_string())?;
    let total_ms = start.elapsed().as_millis() as f64;

    let certs = peer_certs.ok_or_else(|| "no SSL certificate found".to_string())?;
    let cert_der = certs.first().ok_or_else(|| "no SSL certificate found".to_string())?;
    let (_, cert) = X509Certificate::from_der(cert_der.as_ref())
        .map_err(|e| format!("parse certificate: {e}"))?;

    let now = Utc::now().timestamp();
    let not_before = cert.validity().not_before.timestamp();
    let not_after = cert.validity().not_after.timestamp();
    let remaining_days = ((not_after - now) as f64 / 3600.0 / 24.0) as i64;
    let is_expired = now > not_after || now < not_before;

    let issuer_orgs = cert
        .issuer()
        .iter_attributes()
        .filter(|a| a.attr_type() == &x509_parser::oid_registry::OID_X509_ORGANIZATION_NAME)
        .filter_map(|a| a.as_str().ok().map(|s| s.to_string()))
        .collect::<Vec<_>>();
    let issuer_cn = cert
        .issuer()
        .iter_attributes()
        .find(|a| a.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME)
        .and_then(|a| a.as_str().ok().map(|s| s.to_string()))
        .unwrap_or_default();
    let subject_cn = cert
        .subject()
        .iter_attributes()
        .find(|a| a.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME)
        .and_then(|a| a.as_str().ok().map(|s| s.to_string()))
        .unwrap_or_default();

    let domain = clean_host_record(&subject_cn);

    let host_record = clean_host_record(&resolved_ip);
    let download_speed = download_speed(body.len(), total_ms);

    Ok(SslCheckDetail {
        cert_validity_days: remaining_days,
        cert_start_time: DateTime::from_timestamp(not_before, 0).unwrap_or_default(),
        cert_end_time: DateTime::from_timestamp(not_after, 0).unwrap_or_default(),
        http_version,
        host_record,
        https_status_code: https_status,
        total_time: total_ms,
        download_speed,
        domain,
        issuer_organization: Some(issuer_orgs),
        issuer_common_name: issuer_cn,
        subject_common_name: subject_cn,
        is_expired,
        is_reachable: true,
    })
}

fn http_version_str(v: reqwest::Version) -> String {
    match v {
        reqwest::Version::HTTP_09 => "HTTP/0.9",
        reqwest::Version::HTTP_10 => "HTTP/1.0",
        reqwest::Version::HTTP_11 => "HTTP/1.1",
        reqwest::Version::HTTP_2 => "HTTP/2.0",
        reqwest::Version::HTTP_3 => "HTTP/3.0",
        _ => "",
    }
    .to_string()
}
