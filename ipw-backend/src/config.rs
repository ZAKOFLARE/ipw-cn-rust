//! 配置系统：setting.json + 环境变量 + 远端配置
//!
//! 优先级：远端配置（REMOTE_CONFIG_URL）> 环境变量 > setting.json
//! access_token 例外：不随远端配置覆盖（环境变量 > setting.json）
//!
//! 对齐 Go 原版 main.go readConfig / applyRemoteConfig，已删除 gh-proxy 与 ipdb 键。

use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::time::Duration;
use tracing::{info, warn};

/// 单栈模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SingleStack {
    #[default]
    Dual,
    Ipv4,
    Ipv6,
}

impl SingleStack {
    pub fn parse(s: &str) -> Self {
        match s.trim().to_lowercase().as_str() {
            "ipv4" => SingleStack::Ipv4,
            "ipv6" => SingleStack::Ipv6,
            _ => SingleStack::Dual,
        }
    }
}

/// 运行时配置
#[derive(Debug, Clone)]
pub struct Setting {
    pub port: u16,
    pub single_stack: SingleStack,
    pub dns_server: String,
    pub block_private_ips: bool,
    pub cors: String,
    pub access_token: String,
    pub remote_config_url: String,
}

/// setting.json 平铺结构（与 Go 原版键名一致）
#[derive(Debug, Default, Deserialize)]
struct FileConfig {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default, rename = "single-stack")]
    single_stack: Option<String>,
    #[serde(default, rename = "dns-server")]
    dns_server: Option<String>,
    #[serde(default, rename = "block-private-ips")]
    block_private_ips: Option<bool>,
    #[serde(default)]
    cors: Option<String>,
    #[serde(default)]
    access_token: Option<String>,
    #[serde(default, rename = "remote-config-url")]
    remote_config_url: Option<String>,
}

impl Setting {
    /// 加载本地配置（setting.json + 环境变量）。远端配置在 [Setting::apply_remote_config] 异步拉取。
    pub fn load_local() -> Self {
        let file = read_file_config();

        // 端口：PORTS（Go 代码实际变量名）与 PORT（README 文档名）都兼容，PORTS 优先
        let port = env_str("PORTS")
            .or_else(|| env_str("PORT"))
            .and_then(|v| v.parse().ok())
            .or(file.port)
            .unwrap_or(8080);

        let single_stack = SingleStack::parse(&env_or(
            "SINGLE_STACK",
            file.single_stack.as_deref().unwrap_or(""),
        ));

        let dns_server = env_or("DNS_SERVER", file.dns_server.as_deref().unwrap_or(""));

        // SSRF 开关：环境变量非 "false"/"0" 即为开启（默认开启，对齐 Go）
        let block_private_ips = env_opt("BLOCK_PRIVATE_IPS")
            .map(|v| v != "false" && v != "0")
            .or(file.block_private_ips)
            .unwrap_or(true);

        let cors = env_or("CORS", file.cors.as_deref().unwrap_or(""));

        let access_token = env_or("ACCESS_TOKEN", file.access_token.as_deref().unwrap_or(""));

        // REMOTE_CONFIG_URL 优先级：环境变量 > setting.json 的 remote-config-url
        let remote_config_url =
            env_or("REMOTE_CONFIG_URL", file.remote_config_url.as_deref().unwrap_or(""));

        let s = Setting {
            port,
            single_stack,
            dns_server,
            block_private_ips,
            cors,
            access_token,
            remote_config_url,
        };

        info!(
            port = s.port,
            single_stack = ?s.single_stack,
            block_private_ips = s.block_private_ips,
            "local config loaded"
        );
        s
    }

    /// 拉取远端配置并覆盖本地值。失败只警告，不回退进程（对齐 Go applyRemoteConfig）。
    pub async fn apply_remote_config(&mut self) {
        let url = self.remote_config_url.clone();
        if url.is_empty() {
            return;
        }

        // 独立客户端，超时 10s（对齐 Go http.Client{Timeout: 10s}）
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("build config client");

        let result = async {
            let resp = client.get(&url).send().await.map_err(|e| e.to_string())?;
            if resp.status() != reqwest::StatusCode::OK {
                return Err(format!("remote config returned status {}", resp.status().as_u16()));
            }
            let body = resp.bytes().await.map_err(|e| e.to_string())?;
            serde_json::from_slice::<HashMap<String, serde_json::Value>>(&body)
                .map_err(|e| format!("invalid remote config JSON: {e}"))
        }
        .await;

        match result {
            Ok(conf) => {
                if let Some(v) = conf_value(&conf, "port") {
                    if let Ok(p) = v.parse::<u16>() {
                        self.port = p;
                    }
                }
                if let Some(v) = conf_value(&conf, "single-stack") {
                    self.single_stack = SingleStack::parse(&v);
                }
                if let Some(v) = conf_value(&conf, "dns-server") {
                    self.dns_server = v;
                }
                if let Some(v) = conf_value(&conf, "cors") {
                    self.cors = v;
                }
                // block-private-ips：允许远端覆盖（v != "false" && v != "0" 视为开启）
                if let Some(v) = conf_value(&conf, "block-private-ips") {
                    self.block_private_ips = v != "false" && v != "0";
                }
                // access_token 不在此覆盖（保持环境变量 > setting.json）
                info!(url, "remote config applied");
            }
            Err(e) => {
                warn!(url, error = %e, "failed to fetch remote config, falling back to local config");
            }
        }
    }
}

fn read_file_config() -> FileConfig {
    match std::fs::read_to_string("setting.json") {
        Ok(data) => match serde_json::from_str::<FileConfig>(&data) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to parse setting.json, using defaults");
                FileConfig::default()
            }
        },
        Err(_) => {
            warn!("setting.json not found, using defaults");
            FileConfig::default()
        }
    }
}

/// 远端配置值转字符串，非空才返回（对齐 Go configValue：空/缺失不覆盖）
fn conf_value(conf: &HashMap<String, serde_json::Value>, key: &str) -> Option<String> {
    let v = conf.get(key)?;
    let s = match v {
        serde_json::Value::String(s) => s.trim().to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        other => other.to_string().trim().to_string(),
    };
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

fn env_str(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.trim().is_empty()).map(|v| v.trim().to_string())
}

fn env_opt(key: &str) -> Option<String> {
    env::var(key).ok()
}

fn env_or(key: &str, fallback: &str) -> String {
    env_str(key).unwrap_or_else(|| fallback.to_string())
}

/// 版本信息（构建时通过环境变量注入，缺失回退默认）
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
