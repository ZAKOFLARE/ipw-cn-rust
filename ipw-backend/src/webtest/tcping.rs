//! TCP 连接测试（对齐 Go 原版 webtest/tcping.go）

use crate::ssrf;
use crate::webtest::dns::{DnsConfig, resolve_a, resolve_aaaa};
use chrono::{DateTime, Local};
use serde::Serialize;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// 单次 TCP 连接测试结果（对齐 TCPingResult）
#[derive(Debug, Clone, Serialize)]
pub struct TcpPingResult {
    #[serde(rename = "ip")]
    pub ip: String,
    #[serde(rename = "port")]
    pub port: String,
    #[serde(rename = "success")]
    pub success: bool,
    #[serde(rename = "rtt")]
    pub rtt: f64,
    #[serde(rename = "error")]
    pub error: String,
    #[serde(rename = "timestamp")]
    pub timestamp: DateTime<Local>,
}

/// 多次 TCP 连接统计（对齐 TCPingStats）
#[derive(Debug, Clone, Default, Serialize)]
pub struct TcpPingStats {
    #[serde(rename = "ip")]
    pub ip: String,
    #[serde(rename = "port")]
    pub port: String,
    #[serde(rename = "sent")]
    pub sent: i64,
    #[serde(rename = "success")]
    pub success: i64,
    #[serde(rename = "loss_rate")]
    pub loss_rate: f64,
    #[serde(rename = "max_rtt")]
    pub max_rtt: f64,
    #[serde(rename = "min_rtt")]
    pub min_rtt: f64,
    #[serde(rename = "avg_rtt")]
    pub avg_rtt: f64,
    #[serde(rename = "results")]
    pub results: Option<Vec<TcpPingResult>>,
}

/// 将主机名解析为指定协议版本的 IP 字符串（对齐 ResolveHost）
pub async fn resolve_host(host: &str, version: &str, dns: &DnsConfig) -> Result<String, String> {
    let clean = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = clean.parse::<IpAddr>() {
        match version {
            "v4" if ip.is_ipv4() => return Ok(ip.to_string()),
            "v6" if ip.is_ipv6() => return Ok(ip.to_string()),
            _ => return Err(format!("host {host} is not a {version} address")),
        }
    }

    let ip_str = if version == "v4" {
        let result = resolve_a(clean, dns).await;
        if result.record.is_empty() {
            return Err(format!("no v4 address found for {host}"));
        }
        result.record[0].clone()
    } else {
        let result = resolve_aaaa(clean, dns).await;
        if result.record.is_empty() {
            return Err(format!("no v6 address found for {host}"));
        }
        result.record[0].clone()
    };

    // SSRF 检查（对齐 Go：解析结果命中私有 IP 拒绝）
    if ssrf::enabled() {
        if let Ok(ip) = ip_str.parse::<IpAddr>() {
            if ssrf::is_private_ip(ip) {
                return Err(format!(
                    "connection to private/internal address {ip_str} is not allowed"
                ));
            }
        }
    }

    Ok(ip_str)
}

/// 单次 TCP 连接测试（对齐 TCPing）
pub async fn tcping(
    host: &str,
    port: &str,
    version: &str,
    timeout: Duration,
    dns: &DnsConfig,
) -> Result<TcpPingResult, String> {
    let ip = resolve_host(host, version, dns).await?;
    let addr: SocketAddr = match version {
        "v6" => format!("[{ip}]:{port}")
            .parse()
            .map_err(|e| format!("invalid address [{ip}]:{port}: {e}"))?,
        _ => format!("{ip}:{port}")
            .parse()
            .map_err(|e| format!("invalid address {ip}:{port}: {e}"))?,
    };

    let start = Instant::now();
    let timestamp = Local::now();
    let result = tokio::time::timeout(timeout, TcpStream::connect(addr)).await;
    let rtt = start.elapsed();

    let mut out = TcpPingResult {
        ip,
        port: port.to_string(),
        success: false,
        rtt: -1.0,
        error: String::new(),
        timestamp,
    };

    match result {
        Ok(Ok(stream)) => {
            drop(stream);
            out.success = true;
            out.rtt = rtt.as_micros() as f64 / 1000.0;
        }
        Ok(Err(e)) => out.error = e.to_string(),
        Err(_) => out.error = "dial tcp: i/o timeout".to_string(),
    }
    Ok(out)
}

/// 多次 TCP 连接测试并统计（对齐 TCPingRun）
pub async fn tcping_run(
    host: &str,
    port: &str,
    count: i64,
    version: &str,
    timeout: Duration,
    interval: Duration,
    dns: &DnsConfig,
) -> Result<TcpPingStats, String> {
    let ip = match resolve_host(host, version, dns).await {
        Ok(ip) => ip,
        Err(e) => {
            // 对齐 Go：解析失败返回带 Error 前缀的统计对象（nil error）
            return Ok(TcpPingStats {
                ip: format!("Error: {e}"),
                port: port.to_string(),
                sent: count,
                success: 0,
                loss_rate: 100.0,
                max_rtt: -1.0,
                min_rtt: -1.0,
                avg_rtt: -1.0,
                results: None,
            });
        }
    };

    let mut stats = TcpPingStats {
        ip,
        port: port.to_string(),
        sent: count,
        success: 0,
        loss_rate: 0.0,
        max_rtt: f64::MIN,
        min_rtt: f64::MAX,
        avg_rtt: 0.0,
        results: Some(Vec::with_capacity(count as usize)),
    };

    let mut total_rtt = 0.0f64;
    let mut success_count = 0i64;

    for i in 0..count {
        let result = tcping(host, port, version, timeout, dns).await?;

        // 先统计再 push（避免 move）
        if result.success {
            success_count += 1;
            total_rtt += result.rtt;
            if result.rtt > stats.max_rtt {
                stats.max_rtt = result.rtt;
            }
            if result.rtt < stats.min_rtt {
                stats.min_rtt = result.rtt;
            }
        }
        if let Some(results) = stats.results.as_mut() {
            results.push(result);
        }

        if i < count - 1 && !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }
    }

    stats.success = success_count;
    // 对齐 Go：round((count-success)*10000/count)/100
    stats.loss_rate = round2((count - success_count) as f64 * 10000.0 / count as f64) / 100.0;

    if success_count > 0 {
        // 对齐 Go：round(totalRTT*100/successCount)/100
        stats.avg_rtt = round2(total_rtt * 100.0 / success_count as f64) / 100.0;
    } else {
        stats.min_rtt = -1.0;
        stats.max_rtt = -1.0;
        stats.avg_rtt = -1.0;
    }

    Ok(stats)
}

/// 四舍五入到整数（对齐 Go math.Round）
fn round2(v: f64) -> f64 {
    v.round()
}

use tokio::net::TcpStream;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rounding_matches_go() {
        // Go: math.Round(25.5) == 26
        assert_eq!(round2(25.5), 26.0);
        assert_eq!(round2(24.5), 25.0);
        assert_eq!(round2(-0.5), -1.0);
    }

    #[tokio::test]
    async fn resolve_host_literal() {
        let dns = DnsConfig::default();
        assert_eq!(resolve_host("1.1.1.1", "v4", &dns).await.unwrap(), "1.1.1.1");
        assert!(resolve_host("1.1.1.1", "v6", &dns).await.is_err());
        assert!(resolve_host("[2606:4700::1111]", "v6", &dns).await.is_ok());
    }

    #[tokio::test]
    async fn tcping_public() {
        let dns = DnsConfig::default();
        let r = tcping("www.baidu.com", "80", "v4", Duration::from_secs(5), &dns)
            .await
            .unwrap();
        assert!(r.success);
        assert!(r.rtt > 0.0);
        assert!(r.error.is_empty());
    }
}
