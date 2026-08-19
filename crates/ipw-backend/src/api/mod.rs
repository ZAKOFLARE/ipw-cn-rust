//! API 层（对齐 Go main.go 的 handler 与路由）
//!
//! 路由：
//!   GET /                      健康检查
//!   GET /v1/detail/*url        网站检测
//!   GET /v1/ssl/*url           SSL 证书检查
//!   GET /v1/speed/:version/*url 网站测速
//!   GET /v1/tcping/:ip         TCP 连接测试
//!   GET /v1/dns/:type/*domain  DNS 解析
//!   GET /v1/dnssec/:domain     DNSSEC 验证
//!   GET /v1/whois/:domain      Whois 查询

pub mod detail;
pub mod dns;
pub mod dnssec;
pub mod speed;
pub mod ssl;
pub mod tcping;
pub mod timing;
pub mod types;
pub mod whois;

use crate::cache::{Cache, SingleFlight};
use crate::config::Setting;
use crate::http::HttpClient;
use crate::ssrf;
use crate::webtest::dns::DnsConfig;
use crate::webtest::whois::WhoisResult;
use axum::{Json, Router, extract::State, routing::get};
use serde_json::json;
use std::sync::Arc;
use types::*;

/// 共享状态
pub struct AppState {
    pub setting: Setting,
    pub http: HttpClient,
    pub dns: DnsConfig,
    pub tls: tokio_rustls::TlsConnector,
    // 缓存（TTL：成功 5min / 失败 30s）
    pub website_cache: Cache<String, WebsiteCheckResult>,
    pub ssl_cache: Cache<String, SslCheckResult>,
    pub ping_cache: Cache<String, TcpPingResult>,
    pub speed_cache: Cache<String, WebsiteSpeedTestResult>,
    pub whois_cache: Cache<String, WhoisResult>,
    // 单飞防击穿
    pub website_sf: SingleFlight<WebsiteCheckResult>,
    pub ssl_sf: SingleFlight<SslCheckResult>,
    pub ping_sf: SingleFlight<TcpPingResult>,
    pub speed_sf: SingleFlight<WebsiteSpeedTestResult>,
}

/// 构建路由
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(health_check))
        .route("/v1/detail/{*url}", get(detail::detail_handler))
        .route("/v1/ssl/{*url}", get(ssl::ssl_handler))
        .route("/v1/speed/{version}/{*url}", get(speed::speed_handler))
        .route("/v1/tcping/{ip}", get(tcping::ping_handler))
        .route("/v1/dns/{rtype}/{*domain}", get(dns::dns_handler))
        .route("/v1/dnssec/{domain}", get(dnssec::dnssec_handler))
        .route("/v1/whois/{domain}", get(whois::whois_handler))
        .with_state(state)
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// URL 规范化（对齐 Go normalizeURL）
pub fn normalize_url(input: &str) -> String {
    let mut s = input.trim().to_string();
    s = s.trim_start_matches('/').to_string();
    if s.starts_with("http://") || s.starts_with("https://") {
        return s;
    }
    if s.starts_with("//") {
        return format!("https:{s}");
    }
    format!("https://{s}")
}

/// SSRF 预检：校验 scheme/host 并解析检查（对齐 Go HasLocalOrPrivateIP 语义）
/// 返回 Ok(hostname)；**仅命中私有 IP 时**返回 Err（触发蜜罐）。
/// 域名解析失败（NXDOMAIN 等）放行，由主请求自然失败（对齐 Go：LookupIP 失败时
/// HasLocalOrPrivateIP 返回 false，走正常检测流程）。
/// 解析用 hickory（119.28.28.28）而非系统 DNS——Windows 系统解析对 NXDOMAIN 有 10s+ 延迟。
pub async fn ssrf_pretest(raw_url: &str, dns_server: &str) -> Result<String, String> {
    if !ssrf::enabled() {
        return Ok(parse_host(raw_url));
    }
    let host = ssrf::validate_url_scheme_and_host(raw_url)?;
    // IP 字面量直接判定
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        ssrf::check_resolved_ips(&host, std::slice::from_ref(&ip))?;
        return Ok(host);
    }
    // 域名：hickory 解析后逐 IP 检查；解析失败放行（不蜜罐）
    if let Ok(resolver) = crate::http::build_resolver(dns_server) {
        if let Ok(lookup) = resolver.lookup_ip(host.as_str()).await {
            let ips: Vec<std::net::IpAddr> = lookup.iter().collect();
            ssrf::check_resolved_ips(&host, &ips)?;
        }
    }
    Ok(host)
}

/// 从 URL 提取 hostname（不校验）
pub fn parse_host(raw_url: &str) -> String {
    url::Url::parse(raw_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default()
}

/// 请求校验中间件：access_token 非空时校验 Authorization 头（对齐 tokenCheck）
pub async fn token_guard(
    State(state): State<Arc<AppState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // 健康检查不校验（对齐 Go：tokenCheck 只挂 /v1 组，/ 直接放行）
    if req.uri().path() == "/" {
        return next.run(req).await;
    }
    let token = &state.setting.access_token;
    if token.is_empty() {
        return next.run(req).await;
    }
    let auth = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if crate::auth::check(auth, token) {
        next.run(req).await
    } else {
        error_json(401, "Unauthorized")
    }
}

/// 健康检查不校验 token（对齐 Go：tokenCheck 只挂 /v1 组，/ 直接放行）

/// 200 JSON 响应
pub(crate) fn ok_json<T: serde::Serialize>(v: &T) -> axum::response::Response {
    axum::response::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_string(v).unwrap()))
        .unwrap()
}

/// 错误 JSON 响应（对齐 Go gin.H{"error": ...}）
pub(crate) fn error_json(status: u16, msg: &str) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(format!(
            r#"{{"error":"{}"}}"#,
            msg.replace('"', "\\\"")
        )))
        .unwrap()
}

/// 指定状态码 + 任意 JSON 对象响应（对齐 Go 的非 error 包装响应，如 speed 的 400 + 对象体）
pub(crate) fn status_json<T: serde::Serialize>(
    status: u16,
    v: &T,
) -> axum::response::Response {
    axum::response::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(axum::body::Body::from(serde_json::to_string(v).unwrap()))
        .unwrap()
}
