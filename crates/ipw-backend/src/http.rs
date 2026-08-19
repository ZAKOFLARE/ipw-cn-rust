//! 双栈出站 HTTP 客户端（对齐 Go 原版 initHTTPClients）
//!
//! - v4/v6 两个独立 client，resolver 层过滤对应协议族并做 SSRF 检查
//! - zstd/gzip/brotli 自动解压（reqwest features）
//! - TLS 忽略证书校验（对齐 Go InsecureSkipVerify: true）
//! - 重定向策略逐跳 SSRF 校验（对齐 SecureCheckRedirect）

use crate::config::Setting;
use crate::ssrf;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::xfer::Protocol;
use hickory_resolver::TokioResolver;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::redirect::{Attempt, Policy};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// reqwest 的 BoxError 别名
type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// 带 SSRF 检查与协议族过滤的 DNS resolver
#[derive(Clone)]
pub struct SsrfResolver {
    inner: TokioResolver,
    /// true: 只返回 IPv6；false: 只返回 IPv4
    v6_only: bool,
}

impl SsrfResolver {
    fn new(inner: TokioResolver, v6_only: bool) -> Self {
        Self { inner, v6_only }
    }
}

impl Resolve for SsrfResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.inner.clone();
        let v6_only = self.v6_only;
        Box::pin(async move {
            let lookup = resolver
                .lookup_ip(name.as_str())
                .await
                .map_err(|e| -> BoxError { e.into() })?;

            let host = name.as_str().to_string();
            let ips: Vec<IpAddr> = lookup.iter().collect();

            // SSRF：解析结果逐 IP 检查，命中私有地址直接拒绝（对齐 Go DialContext 行为）
            if ssrf::enabled() {
                ssrf::check_resolved_ips(&host, &ips)
                    .map_err(|e| -> BoxError { std::io::Error::new(std::io::ErrorKind::PermissionDenied, e).into() })?;
            }

            let addrs: Vec<SocketAddr> = ips
                .into_iter()
                .filter(|ip| if v6_only { ip.is_ipv6() } else { ip.is_ipv4() })
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();

            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// 构建 hickory resolver：配置了 dns-server 用指定服务器，否则默认 119.28.28.28:53
/// （对齐 Go：webtest 的 dnsServer 初始值即 119.28.28.28:53；不用系统 DNS，避免 Windows 上
/// 系统解析器对 NXDOMAIN 查询出现 10s+ 延迟）
pub(crate) fn build_resolver(dns_server: &str) -> Result<TokioResolver, BoxError> {
    let dns_server = dns_server.trim();
    let dns_server = if dns_server.is_empty() {
        crate::webtest::dns::DEFAULT_UDP_SERVER
    } else {
        dns_server
    };

    let addr = SocketAddr::from_str(dns_server)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid dns-server {dns_server}: {e}")))?;
    let mut config = ResolverConfig::new();
    config.add_name_server(NameServerConfig::new(addr, Protocol::Udp));
    Ok(TokioResolver::builder_with_config(config, TokioConnectionProvider::default()).build())
}

/// 重定向 SSRF 校验（对齐 Go SecureCheckRedirect）
fn secure_redirect_policy() -> Policy {
    Policy::custom(move |attempt: Attempt| {
        if !ssrf::enabled() {
            return attempt.follow();
        }
        if let Some(host) = attempt.url().host_str() {
            // IP 字面量直接判定
            if let Ok(ip) = host.parse::<IpAddr>() {
                if ssrf::is_private_ip(ip) {
                    tracing::warn!("blocked redirect to private IP {host} -> {ip}");
                    return attempt.stop();
                }
                return attempt.follow();
            }
            // 域名：同步解析并检查（对齐 Go net.LookupIP，阻塞可接受）
            if let Ok(ips) = (host, 0).to_socket_addrs() {
                let ip_list: Vec<IpAddr> = ips.map(|sa| sa.ip()).collect();
                if ssrf::check_resolved_ips(host, &ip_list).is_err() {
                    return attempt.stop();
                }
            }
        }
        attempt.follow()
    })
}

/// 双栈 HTTP 客户端
pub struct HttpClient {
    pub v4: reqwest::Client,
    pub v6: reqwest::Client,
}

impl HttpClient {
    pub fn new(setting: &Setting) -> Result<Self, BoxError> {
        let base = build_resolver(&setting.dns_server)?;

        let mut clients = Vec::new();
        for v6_only in [false, true] {
            let resolver = SsrfResolver::new(base.clone(), v6_only);
            let client = reqwest::Client::builder()
                .dns_resolver(Arc::new(resolver))
                .redirect(secure_redirect_policy())
                .timeout(Duration::from_secs(10))
                .connect_timeout(Duration::from_secs(10))
                // 对齐 Go：TLS InsecureSkipVerify
                .danger_accept_invalid_certs(true)
                .build()?;
            clients.push(client);
        }

        let (v4, v6) = (clients.remove(0), clients.remove(0));
        Ok(Self { v4, v6 })
    }

    /// 按协议版本取 client
    pub fn pick(&self, version: &str) -> &reqwest::Client {
        if version == "v6" { &self.v6 } else { &self.v4 }
    }
}

/// 域名解析辅助：解析 host 到指定协议族的 IP 列表（供 tcping/ssl 等手动连接场景）
pub async fn resolve_host(
    host: &str,
    v6: bool,
    dns: &crate::webtest::dns::DnsConfig,
) -> Result<Vec<IpAddr>, String> {
    // IP 字面量直接返回
    if let Ok(ip) = host.parse::<IpAddr>() {
        if v6 && !ip.is_ipv6() {
            return Err("host has no IPv6 address".to_string());
        }
        if !v6 && !ip.is_ipv4() {
            return Err("host has no IPv4 address".to_string());
        }
        return Ok(vec![ip]);
    }

    let resolver = build_resolver(&dns.server).map_err(|e| e.to_string())?;
    let lookup = resolver
        .lookup_ip(host)
        .await
        .map_err(|e| e.to_string())?;
    let ips: Vec<IpAddr> = lookup
        .iter()
        .filter(|ip| if v6 { ip.is_ipv6() } else { ip.is_ipv4() })
        .collect();
    if ips.is_empty() {
        return Err(format!(
            "host has no {} address",
            if v6 { "IPv6" } else { "IPv4" }
        ));
    }
    Ok(ips)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webtest::dns::DnsConfig;

    fn test_dns() -> DnsConfig {
        DnsConfig::default()
    }

    #[tokio::test]
    async fn resolve_v4_v6() {
        let v4 = resolve_host("www.baidu.com", false, &test_dns()).await.unwrap();
        assert!(!v4.is_empty());
        assert!(v4.iter().all(|ip| ip.is_ipv4()));
    }

    #[test]
    fn literal_ip_resolution() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let ips = rt.block_on(resolve_host("1.1.1.1", false, &test_dns())).unwrap();
        assert_eq!(ips, vec!["1.1.1.1".parse::<IpAddr>().unwrap()]);
    }
}
