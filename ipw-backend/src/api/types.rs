//! 各接口的响应结构体（JSON 字段与 Go 原版逐字对齐）
//! 对齐 main.go 的 WebsiteCheckResult / SSLCheckResult / TCPingResult / WebsiteSpeedTestResult

use crate::cache::FailureAware;
use crate::webtest::tcping::TcpPingStats;
use crate::webtest::whois::WhoisResult;
use chrono::{DateTime, Utc};
use serde::Serialize;

// ==================== detail ====================

/// 网站检测结果（双栈容器，对齐 WebsiteCheckResult）
#[derive(Debug, Clone, Serialize)]
pub struct WebsiteCheckResult {
    #[serde(rename = "ipv4")]
    pub ipv4: Option<WebsiteCheckDetail>,
    #[serde(rename = "ipv6")]
    pub ipv6: Option<WebsiteCheckDetail>,
}

impl FailureAware for WebsiteCheckResult {
    fn is_failure(&self) -> bool {
        let v4_fail = self.ipv4.as_ref().map(|d| !d.is_reachable).unwrap_or(true);
        let v6_fail = self.ipv6.as_ref().map(|d| !d.is_reachable).unwrap_or(true);
        // 对齐 Go：任一栈不可达即视为软失败（30s 后删缓存）
        v4_fail || v6_fail
    }
}

/// 网站检测详情（对齐 WebsiteCheckDetail）
#[derive(Debug, Clone, Serialize)]
pub struct WebsiteCheckDetail {
    #[serde(rename = "host_record")]
    pub host_record: String,
    #[serde(rename = "http_status_code")]
    pub http_status_code: i64,
    #[serde(rename = "https_status_code")]
    pub https_status_code: i64,
    #[serde(rename = "dns_lookup_time")]
    pub dns_lookup_time: f64,
    #[serde(rename = "tcp_connect_time")]
    pub tcp_connect_time: f64,
    #[serde(rename = "http_connect_time")]
    pub http_connect_time: f64,
    #[serde(rename = "first_byte_time")]
    pub first_byte_time: f64,
    #[serde(rename = "total_time")]
    pub total_time: f64,
    #[serde(rename = "page_size")]
    pub page_size: i64,
    #[serde(rename = "download_speed")]
    pub download_speed: f64,
    #[serde(rename = "is_reachable")]
    pub is_reachable: bool,
}

impl WebsiteCheckDetail {
    /// 错误详情（对齐 Go handler 中的错误构造）
    pub fn error(err: &str) -> Self {
        Self {
            host_record: format!("Error: {err}"),
            http_status_code: 0,
            https_status_code: 0,
            dns_lookup_time: 0.0,
            tcp_connect_time: 0.0,
            http_connect_time: 0.0,
            first_byte_time: 0.0,
            total_time: 0.0,
            page_size: 0,
            download_speed: 0.0,
            is_reachable: false,
        }
    }

    /// skipped 详情（对齐 Go "Skipped due to SINGLE_STACK=..."）
    pub fn skipped(msg: &str) -> Self {
        Self {
            host_record: msg.to_string(),
            http_status_code: 0,
            https_status_code: 0,
            dns_lookup_time: 0.0,
            tcp_connect_time: 0.0,
            http_connect_time: 0.0,
            first_byte_time: 0.0,
            total_time: 0.0,
            page_size: 0,
            download_speed: 0.0,
            is_reachable: false,
        }
    }

    /// SSRF 命中的蜜罐响应（对齐 fakePerfectWebsiteResult：入参为完整 URL，内部去 scheme 前缀）
    pub fn fake_perfect(url: &str) -> Self {
        // 对齐 Go fakePerfectWebsiteResult 的 cleanHost 逻辑（只去 http(s):// 前缀，保留路径）
        let clean = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        Self {
            host_record: clean.to_string(),
            http_status_code: 200,
            https_status_code: 200,
            dns_lookup_time: 0.5,
            tcp_connect_time: 1.0,
            http_connect_time: 1.5,
            first_byte_time: 2.0,
            total_time: 100.0,
            page_size: 52428,
            download_speed: 512.0,
            is_reachable: true,
        }
    }
}

// ==================== ssl ====================

/// SSL 检查结果（双栈容器，对齐 SSLCheckResult）
#[derive(Debug, Clone, Serialize)]
pub struct SslCheckResult {
    #[serde(rename = "ipv4")]
    pub ipv4: Option<SslCheckDetail>,
    #[serde(rename = "ipv6")]
    pub ipv6: Option<SslCheckDetail>,
}

impl FailureAware for SslCheckResult {
    fn is_failure(&self) -> bool {
        let v4_fail = self.ipv4.as_ref().map(|d| !d.is_reachable).unwrap_or(true);
        let v6_fail = self.ipv6.as_ref().map(|d| !d.is_reachable).unwrap_or(true);
        v4_fail || v6_fail
    }
}

/// SSL 检查详情（对齐 SSLCheckDetail）
#[derive(Debug, Clone, Serialize)]
pub struct SslCheckDetail {
    #[serde(rename = "cert_validity_days")]
    pub cert_validity_days: i64,
    #[serde(rename = "cert_start_time")]
    pub cert_start_time: DateTime<Utc>,
    #[serde(rename = "cert_end_time")]
    pub cert_end_time: DateTime<Utc>,
    #[serde(rename = "http_version")]
    pub http_version: String,
    #[serde(rename = "host_record")]
    pub host_record: String,
    #[serde(rename = "https_status_code")]
    pub https_status_code: i64,
    #[serde(rename = "total_time")]
    pub total_time: f64,
    #[serde(rename = "download_speed")]
    pub download_speed: f64,
    #[serde(rename = "domain")]
    pub domain: String,
    #[serde(rename = "issuer_organization")]
    pub issuer_organization: Option<Vec<String>>,
    #[serde(rename = "issuer_common_name")]
    pub issuer_common_name: String,
    #[serde(rename = "subject_common_name")]
    pub subject_common_name: String,
    #[serde(rename = "is_expired")]
    pub is_expired: bool,
    #[serde(rename = "is_reachable")]
    pub is_reachable: bool,
}

impl SslCheckDetail {
    /// 错误详情（对齐 Go：错误路径时间字段为零值 time.Time{}，即 1970-01-01）
    pub fn error(err: &str) -> Self {
        Self {
            cert_validity_days: 0,
            cert_start_time: DateTime::UNIX_EPOCH,
            cert_end_time: DateTime::UNIX_EPOCH,
            http_version: String::new(),
            host_record: format!("Error: {err}"),
            https_status_code: 0,
            total_time: 0.0,
            download_speed: 0.0,
            domain: String::new(),
            issuer_organization: None,
            issuer_common_name: String::new(),
            subject_common_name: String::new(),
            is_expired: true,
            is_reachable: false,
        }
    }

    pub fn skipped(msg: &str) -> Self {
        Self {
            cert_validity_days: 0,
            cert_start_time: DateTime::UNIX_EPOCH,
            cert_end_time: DateTime::UNIX_EPOCH,
            http_version: String::new(),
            host_record: msg.to_string(),
            https_status_code: 0,
            total_time: 0.0,
            download_speed: 0.0,
            domain: String::new(),
            issuer_organization: None,
            issuer_common_name: String::new(),
            subject_common_name: String::new(),
            is_expired: true,
            is_reachable: false,
        }
    }

    /// SSRF 命中的无效证书响应（对齐 fakeInvalidSSLResult：CertStartTime/EndTime 为零值 time.Time{}）
    pub fn fake_invalid(host: &str) -> Self {
        Self {
            cert_validity_days: 0,
            cert_start_time: DateTime::UNIX_EPOCH,
            cert_end_time: DateTime::UNIX_EPOCH,
            http_version: String::new(),
            host_record: host.to_string(),
            https_status_code: 0,
            total_time: 0.0,
            download_speed: 0.0,
            domain: host.to_string(),
            issuer_organization: None,
            issuer_common_name: "Invalid Certificate".to_string(),
            subject_common_name: host.to_string(),
            is_expired: true,
            is_reachable: false,
        }
    }
}

// ==================== tcping ====================

/// TCPing 结果（双栈容器，对齐 TCPingResult）
#[derive(Debug, Clone, Serialize)]
pub struct TcpPingResult {
    #[serde(rename = "ipv4")]
    pub ipv4: Option<TcpPingStats>,
    #[serde(rename = "ipv6")]
    pub ipv6: Option<TcpPingStats>,
}

impl FailureAware for TcpPingResult {
    fn is_failure(&self) -> bool {
        // 对齐 Go：双栈都 Error 才视为失败
        let v4_fail = self
            .ipv4
            .as_ref()
            .map(|s| s.ip.starts_with("Error:"))
            .unwrap_or(true);
        let v6_fail = self
            .ipv6
            .as_ref()
            .map(|s| s.ip.starts_with("Error:"))
            .unwrap_or(true);
        v4_fail && v6_fail
    }
}

// ==================== speed ====================

/// 网站测速结果（对齐 WebsiteSpeedTestResult）
#[derive(Debug, Clone, Serialize)]
pub struct WebsiteSpeedTestResult {
    #[serde(rename = "version")]
    pub version: String,
    #[serde(rename = "host_record")]
    pub host_record: String,
    #[serde(rename = "http_status_code")]
    pub http_status_code: i64,
    #[serde(rename = "https_status_code")]
    pub https_status_code: i64,
    #[serde(rename = "dns_lookup_time")]
    pub dns_lookup_time: f64,
    #[serde(rename = "tcp_connect_time")]
    pub tcp_connect_time: f64,
    #[serde(rename = "http_connect_time")]
    pub http_connect_time: f64,
    #[serde(rename = "first_byte_time")]
    pub first_byte_time: f64,
    #[serde(rename = "total_time")]
    pub total_time: f64,
    #[serde(rename = "page_size")]
    pub page_size: i64,
    #[serde(rename = "download_speed")]
    pub download_speed: f64,
    #[serde(rename = "message")]
    pub message: String,
    #[serde(rename = "headers")]
    pub headers: String,
    #[serde(rename = "is_reachable")]
    pub is_reachable: bool,
}

impl FailureAware for WebsiteSpeedTestResult {
    fn is_failure(&self) -> bool {
        !self.is_reachable
    }
}

// ==================== whois ====================

// 对齐 Go：whois 缓存无条件 5min（whoisHandler 无 30s 删除逻辑），
// 因此 FailureAware 恒返回 false（永远按成功结果缓存）
impl FailureAware for WhoisResult {
    fn is_failure(&self) -> bool {
        false
    }
}
