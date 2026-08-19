//! 中间层配置：平铺 setting.json + 环境变量覆盖
//!
//! 优先级：环境变量 > setting.json > 默认值
//! 键名与前端 config/index.ts 保持一致（硬约束，不可改名）。
//! 对齐 Go 原版 middleware-go/main.go readConfig。

use serde::Deserialize;
use std::env;
use std::path::Path;
use tracing::info;

/// 上游节点 { label, id, url }
#[derive(Debug, Clone, Deserialize)]
pub struct ApiInfo {
    /// 节点展示名（对齐前端 config/index.ts 的 label；转发逻辑不读取，仅供配置标识）
    #[serde(default)]
    #[allow(dead_code)]
    pub label: String,
    pub id: String,
    pub url: String,
}

/// tcping/speed 的分栈节点配置（JSON 键对齐前端 config/index.ts：DualStack/IPv4/IPv6）
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StackConfig {
    #[serde(default, rename = "DualStack")]
    pub dual_stack: Vec<ApiInfo>,
    #[serde(default, rename = "IPv4")]
    pub ipv4: Vec<ApiInfo>,
    #[serde(default, rename = "IPv6")]
    pub ipv6: Vec<ApiInfo>,
}

/// setting.json 平铺结构（键名与前端 config/index.ts 一致，逐字段显式 rename）
#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    port: Option<PortValue>,
    #[serde(default, rename = "httpTimeoutSeconds")]
    http_timeout_seconds: Option<u64>,
    #[serde(default)]
    cors: Option<String>,
    #[serde(default, rename = "apiBaseUrls")]
    api_base_urls: Vec<ApiInfo>,
    #[serde(default, rename = "IPLocationAPIs")]
    ip_location_apis: Vec<ApiInfo>,
    #[serde(default, rename = "TCPing")]
    tcping: StackConfig,
    #[serde(default, rename = "SpeedTest")]
    speed_test: StackConfig,
    #[serde(default, rename = "NSLookup")]
    ns_lookup: Vec<ApiInfo>,
    #[serde(default, rename = "apiKeys")]
    api_keys: std::collections::HashMap<String, String>,
}

/// port 兼容 JSON 字符串与数字（对齐 Go 的 stringOrNumber）
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum PortValue {
    Str(String),
    Num(u64),
}

impl PortValue {
    fn to_string(&self) -> String {
        match self {
            PortValue::Str(s) => s.clone(),
            PortValue::Num(n) => n.to_string(),
        }
    }
}

/// 运行时中间层配置
#[derive(Debug, Clone)]
pub struct MiddlewareConfig {
    pub port: String,
    pub http_timeout_seconds: u64,
    /// CORS 原始配置字符串（仅在加载时用于拆分 accept_domains，运行期不读取）
    #[allow(dead_code)]
    pub cors: String,
    pub accept_domains: Vec<String>,
    pub api_base_urls: Vec<ApiInfo>,
    pub ip_location_apis: Vec<ApiInfo>,
    pub tcping: StackConfig,
    pub speed_test: StackConfig,
    pub ns_lookup: Vec<ApiInfo>,
    pub api_keys: std::collections::HashMap<String, String>,
}

impl MiddlewareConfig {
    /// 加载配置。节点列表全空时报错退出（防止错误配置静默空跑，对齐 Go）。
    pub fn load() -> Self {
        let path = find_config_path();
        let mut file = match &path {
            Some(p) => match std::fs::read_to_string(p) {
                Ok(data) => match serde_json::from_str::<FileConfig>(&data) {
                    Ok(c) => {
                        info!(path = %p, "config loaded");
                        c
                    }
                    Err(e) => panic!("parse {p}: {e}"),
                },
                Err(e) => panic!("read {p}: {e}"),
            },
            None => panic!("setting.json not found (set SETTING_FILE to specify its path)"),
        };

        // 环境变量覆盖（优先级：环境变量 > setting.json）
        if let Some(v) = env::var("PORT").ok().filter(|v| !v.is_empty()) {
            file.port = Some(PortValue::Str(v));
        }
        if let Some(v) = env::var("HTTP_TIMEOUT").ok().filter(|v| !v.is_empty()) {
            file.http_timeout_seconds = Some(
                v.parse().unwrap_or_else(|e| panic!("parse env HTTP_TIMEOUT: {e}")),
            );
        }
        if let Some(v) = env::var("CORS").ok().filter(|v| !v.is_empty()) {
            file.cors = Some(v);
        }
        if let Some(raw) = env::var("API_BASE_URLS").ok().filter(|v| !v.is_empty()) {
            file.api_base_urls = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse env API_BASE_URLS: {e}"));
        }
        if let Some(raw) = env::var("IP_LOCATION_APIS").ok().filter(|v| !v.is_empty()) {
            file.ip_location_apis = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse env IP_LOCATION_APIS: {e}"));
        }
        if let Some(raw) = env::var("TCPING").ok().filter(|v| !v.is_empty()) {
            file.tcping =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse env TCPING: {e}"));
        }
        if let Some(raw) = env::var("SPEED_TEST").ok().filter(|v| !v.is_empty()) {
            file.speed_test = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse env SPEED_TEST: {e}"));
        }
        if let Some(raw) = env::var("NS_LOOKUP").ok().filter(|v| !v.is_empty()) {
            file.ns_lookup =
                serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse env NS_LOOKUP: {e}"));
        }
        if let Some(raw) = env::var("APIKEYS").ok().filter(|v| !v.is_empty()) {
            file.api_keys = serde_json::from_str(&raw)
                .unwrap_or_else(|e| panic!("parse env APIKEYS: {e}"));
        }

        // 校验：所有节点列表全空则拒绝启动
        let has_endpoints = !file.api_base_urls.is_empty()
            || !file.ns_lookup.is_empty()
            || !file.ip_location_apis.is_empty()
            || !file.tcping.dual_stack.is_empty()
            || !file.tcping.ipv4.is_empty()
            || !file.tcping.ipv6.is_empty()
            || !file.speed_test.dual_stack.is_empty()
            || !file.speed_test.ipv4.is_empty()
            || !file.speed_test.ipv6.is_empty();
        if !has_endpoints {
            panic!("invalid config: missing endpoint lists (expected flat middleware config)");
        }

        let cors = file.cors.clone().unwrap_or_default();
        let accept_domains = if cors.is_empty() {
            Vec::new()
        } else {
            cors.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
        };

        let port = file
            .port
            .map(|p| p.to_string())
            .or_else(|| env::var("PORT").ok())
            .filter(|p| !p.is_empty())
            .unwrap_or_else(|| "8080".to_string());

        MiddlewareConfig {
            port,
            http_timeout_seconds: file.http_timeout_seconds.unwrap_or(30),
            cors,
            accept_domains,
            api_base_urls: file.api_base_urls,
            ip_location_apis: file.ip_location_apis,
            tcping: file.tcping,
            speed_test: file.speed_test,
            ns_lookup: file.ns_lookup,
            api_keys: file.api_keys,
        }
    }
}

/// 查找配置文件：SETTING_FILE 环境变量 > ./setting.json > ../setting.json
fn find_config_path() -> Option<String> {
    if let Some(p) = env::var("SETTING_FILE").ok().filter(|v| !v.is_empty()) {
        return Some(p);
    }
    for candidate in ["setting.json", "../setting.json"] {
        if Path::new(candidate).exists() {
            return Some(candidate.to_string());
        }
    }
    None
}

/// 版本信息
pub const VERSION: &str = match option_env!("CARGO_PKG_VERSION") {
    Some(v) => v,
    None => "0.0.0",
};
pub const COMMIT: &str = match option_env!("GIT_COMMIT_HASH") {
    Some(v) => v,
    None => "unknown",
};
pub const BUILD_TIME: &str = match option_env!("BUILD_TIME") {
    Some(v) => v,
    None => "unknown",
};
