mod api;
mod auth;
mod cache;
mod config;
mod http;
mod ssrf;
mod webtest;

use axum::Router;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    // 统一 rustls CryptoProvider（reqwest 的 rustls-tls 会同时引入 aws-lc-rs 与 ring，
    // 显式安装 ring provider 避免运行时冲突）
    let _ = rustls::crypto::ring::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=info".to_string()),
        )
        .init();

    // -v / --version / version 参数打印版本信息（对齐 Go 原版行为）
    for arg in std::env::args().skip(1) {
        if arg == "-v" || arg == "--version" || arg == "version" {
            println!("LEMON IPW TEST NODE RUST VERSION {}", config::VERSION);
            println!("COMMIT {}", config::COMMIT);
            println!("BUILD_TIME {}", config::BUILD_TIME);
            return;
        }
    }

    let mut setting = config::Setting::load_local();
    setting.apply_remote_config().await;

    // SSRF 开关同步到全局（配置加载后）
    ssrf::set_enabled(setting.block_private_ips);

    let http_client = http::HttpClient::new(&setting)
        .unwrap_or_else(|e| panic!("failed to init http clients: {e}"));
    let tls = api::timing::build_tls_connector();
    let dns = webtest::dns::DnsConfig {
        server: setting.dns_server.clone(),
    };

    let state = Arc::new(api::AppState {
        setting,
        http: http_client,
        dns,
        tls: (*tls).clone(),
        website_cache: cache::Cache::new(),
        ssl_cache: cache::Cache::new(),
        ping_cache: cache::Cache::new(),
        speed_cache: cache::Cache::new(),
        whois_cache: cache::Cache::new(),
        website_sf: cache::SingleFlight::new(),
        ssl_sf: cache::SingleFlight::new(),
        ping_sf: cache::SingleFlight::new(),
        speed_sf: cache::SingleFlight::new(),
    });

    let app = build_app(state.clone());
    let addr = format!("0.0.0.0:{}", state.setting.port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));
    tracing::info!("ipw-backend listening on http://{addr}");
    axum::serve(listener, app).await.expect("server error");
}

/// 构建应用（拆分便于测试）
fn build_app(state: Arc<api::AppState>) -> Router {
    let cors = build_cors(&state.setting.cors);
    api::router(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api::token_guard,
        ))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
}

/// CORS（对齐 Go：允许域名列表为空则允许所有）
fn build_cors(cors_config: &str) -> CorsLayer {
    let domains: Vec<&str> = cors_config.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
    let base = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::HEAD,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::ORIGIN,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT,
            axum::http::header::AUTHORIZATION,
        ])
        .max_age(std::time::Duration::from_secs(86400));
    if domains.is_empty() {
        base.allow_origin(Any)
    } else {
        let origins: Vec<axum::http::HeaderValue> = domains
            .iter()
            .filter_map(|d| d.parse().ok())
            .collect();
        base.allow_origin(origins)
    }
}
