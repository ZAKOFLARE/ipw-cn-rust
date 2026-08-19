//! 连接阶段计时（DNS 解析 / TCP 连接 / TLS 握手）
//!
//! 对齐 Go 的 resty EnableTrace 四段耗时语义：
//! - DNSLookupTime：手动解析计时（对齐 Go 的 measureDNSTime fallback）
//! - TCPConnectTime：TcpStream::connect 计时
//! - HTTPConnectTime：连接建立含 TLS 握手（Go ConnTime 语义）
//! - FirstByteTime：由调用方在读取响应体首块时记录

use crate::http::resolve_host;
use crate::webtest::dns::DnsConfig;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

/// 连接测量结果
pub struct Timing {
    pub dns_lookup_ms: f64,
    pub tcp_connect_ms: f64,
    pub http_connect_ms: f64,
    pub resolved_ip: String,
}

/// 对目标 host 做一次连接测量（DNS + TCP [+ TLS]），不发送业务请求
pub async fn measure_connection(
    host: &str,
    port: u16,
    v6: bool,
    dns: &DnsConfig,
    tls: &tokio_rustls::TlsConnector,
) -> Timing {
    let dns_start = Instant::now();
    let ips = resolve_host(host, v6, dns).await.unwrap_or_default();
    let dns_ms = dns_start.elapsed().as_secs_f64() * 1000.0;

    let mut tcp_ms = 0.0f64;
    let mut http_ms = 0.0f64;
    let mut resolved_ip = String::new();

    if let Some(ip) = ips.first() {
        resolved_ip = ip.to_string();
        let addr = SocketAddr::new(*ip, port);

        // 连接超时 10s（对齐 Go dialer Timeout: 10s）
        let tcp_start = Instant::now();
        let connect = tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(addr)).await;
        if let Ok(Ok(stream)) = connect {
            tcp_ms = tcp_start.elapsed().as_secs_f64() * 1000.0;

            // HTTPS 端口补 TLS 握手计时
            if port == 443 {
                let tls_start = Instant::now();
                if let Ok(name) = rustls::pki_types::ServerName::try_from(host.to_string()) {
                    let tls_connect =
                        tokio::time::timeout(Duration::from_secs(10), tls.connect(name, stream)).await;
                    if let Ok(Ok(_tls_stream)) = tls_connect {
                        http_ms = tcp_ms + tls_start.elapsed().as_secs_f64() * 1000.0;
                    } else {
                        http_ms = tcp_ms;
                    }
                } else {
                    http_ms = tcp_ms;
                }
            } else {
                http_ms = tcp_ms;
            }
        }
    }

    Timing {
        dns_lookup_ms: dns_ms,
        tcp_connect_ms: tcp_ms,
        http_connect_ms: http_ms,
        resolved_ip,
    }
}

/// 从 IP 提取 host_record（对齐 cleanHostRecord：去端口与方括号）
pub fn clean_host_record(ip: &str) -> String {
    let ip: IpAddr = match ip.parse() {
        Ok(ip) => ip,
        Err(_) => return ip.to_string(),
    };
    ip.to_string()
}

/// 下载速度（对齐 Go：body_len / 1024 / (total_ms / 1000)）
pub fn download_speed(body_len: usize, total_ms: f64) -> f64 {
    if total_ms > 0.0 {
        body_len as f64 / 1024.0 / (total_ms / 1000.0)
    } else {
        0.0
    }
}

/// TLS 连接器（忽略证书校验，对齐 Go InsecureSkipVerify: true）
pub fn build_tls_connector() -> Arc<tokio_rustls::TlsConnector> {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::crypto::ring::default_provider;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth();

    Arc::new(tokio_rustls::TlsConnector::from(Arc::new(config)))
}
