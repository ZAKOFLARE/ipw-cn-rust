//! ipw-middleware：独立转发中间件（Rust 重构）
//!
//! 对应 Go 原版 middleware-go/main.go。
//! 路由：
//!   GET /                     → {"status":"ok"}
//!   GET /v1/*                 → 转发
//!   GET /middleware/*         → 转发

mod config;
mod forward;

use axum::{Json, Router, routing::get};
use serde_json::json;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,tower_http=info".to_string()),
        )
        .init();

    for arg in std::env::args().skip(1) {
        if arg == "-v" || arg == "--version" || arg == "version" {
            println!("IPW-MIDDLEWARE VERSION {}", config::VERSION);
            println!("COMMIT {}", config::COMMIT);
            println!("BUILD_TIME {}", config::BUILD_TIME);
            return;
        }
    }

    let setting = config::MiddlewareConfig::load();
    let port = port_of(&setting.port).to_string();

    let cors = build_cors(&setting.accept_domains);
    let app = Router::new()
        .route("/", get(health_check))
        .route("/v1/{*slug}", get(forward::middleware_handler))
        .route("/middleware/{*slug}", get(forward::middleware_handler))
        .with_state(Arc::new(setting))
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // 显式 0.0.0.0：Windows 上 tokio 对 ":port" 会解析到链路本地 IPv6 地址（fe80::%x），导致 v4 客户端无法访问
    let listen_addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&listen_addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {listen_addr}: {e}"));
    tracing::info!("ipw-middleware listening on http://{listen_addr}");
    axum::serve(listener, app).await.expect("server error");
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({ "status": "ok" }))
}

/// CORS（对齐 Go：域名列表为空则允许所有）
fn build_cors(accept_domains: &[String]) -> CorsLayer {
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
    if accept_domains.is_empty() {
        base.allow_origin(Any)
    } else {
        let origins: Vec<axum::http::HeaderValue> = accept_domains
            .iter()
            .filter_map(|d| d.parse().ok())
            .collect();
        base.allow_origin(origins)
    }
}

fn port_of(port: &str) -> &str {
    if port.is_empty() { "8080" } else { port }
}
