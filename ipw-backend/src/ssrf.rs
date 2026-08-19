//! SSRF 防护（对齐 Go 原版 ssrf/ssrf.go）
//!
//! 覆盖：RFC 1918 私有段、ULA fc00::/7、回环、链路本地、未指定地址；
//! IPv4-mapped IPv6（::ffff:a.b.c.d）按映射后的 IPv4 判定。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicBool, Ordering};

/// SSRF 防护全局开关（默认开启，配置加载时可关闭）
static BLOCK_PRIVATE_IPS: AtomicBool = AtomicBool::new(true);

pub fn set_enabled(v: bool) {
    BLOCK_PRIVATE_IPS.store(v, Ordering::Relaxed);
}

pub fn enabled() -> bool {
    BLOCK_PRIVATE_IPS.load(Ordering::Relaxed)
}

/// 判断 IP 是否属于私有/内部地址段（对齐 Go net.IP.IsPrivate/IsLoopback/IsLinkLocalUnicast/IsUnspecified）
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => {
            // IPv4-mapped IPv6（::ffff:a.b.c.d）按 IPv4 判定
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_private_ipv4(v4);
            }
            let o = v6.octets();
            // 未指定 ::（RFC 4291）
            if v6 == Ipv6Addr::UNSPECIFIED {
                return true;
            }
            // 回环 ::1
            if v6 == Ipv6Addr::LOCALHOST {
                return true;
            }
            // ULA fc00::/7（RFC 4193）
            if o[0] & 0xfe == 0xfc {
                return true;
            }
            // 链路本地 fe80::/10（RFC 4291）
            if o[0] == 0xfe && o[1] & 0xc0 == 0x80 {
                return true;
            }
            false
        }
    }
}

fn is_private_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    // RFC 1918：10.0.0.0/8、172.16.0.0/12、192.168.0.0/16
    o[0] == 10
        || (o[0] == 172 && o[1] & 0xf0 == 16)
        || (o[0] == 192 && o[1] == 168)
        // 回环 127.0.0.0/8
        || o[0] == 127
        // 链路本地 169.254.0.0/16（RFC 3927）
        || (o[0] == 169 && o[1] == 254)
        // 未指定 0.0.0.0
        || (o[0] == 0 && o[1] == 0 && o[2] == 0 && o[3] == 0)
}

/// 对一组已解析 IP 做校验，命中私有地址即拒绝。
/// 返回 Err 时携带被拦截的 host 与 ip（对齐 Go 的日志与错误文案）。
pub fn check_resolved_ips(host: &str, ips: &[IpAddr]) -> Result<(), String> {
    for ip in ips {
        if is_private_ip(*ip) {
            tracing::warn!("blocked request to private IP {host} -> {ip}");
            return Err("request to private/internal address is not allowed".to_string());
        }
    }
    Ok(())
}

/// URL 预检：scheme 白名单 + host 非空（对齐 Go ValidateOutboundTarget 的 scheme 部分）。
/// 返回 hostname（已去 IPv6 括号）。
pub fn validate_url_scheme_and_host(raw: &str) -> Result<String, String> {
    let parsed = url::Url::parse(raw.trim()).map_err(|e| e.to_string())?;
    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!("invalid scheme: {scheme}"));
    }
    let host = parsed.host_str().ok_or_else(|| "empty host".to_string())?.to_string();
    if host.is_empty() {
        return Err("empty host".to_string());
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn private_ipv4() {
        for ip in [
            "10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1",
            "192.168.255.255", "127.0.0.1", "127.8.8.8", "169.254.1.1", "0.0.0.0",
        ] {
            assert!(is_private_ip(ip.parse::<IpAddr>().unwrap()), "{ip} should be private");
        }
    }

    #[test]
    fn public_ipv4() {
        for ip in ["8.8.8.8", "1.1.1.1", "172.32.0.1", "169.255.1.1", "192.169.1.1", "114.114.114.114"] {
            assert!(!is_private_ip(ip.parse::<IpAddr>().unwrap()), "{ip} should be public");
        }
    }

    #[test]
    fn private_ipv6() {
        for ip in ["::1", "::", "fc00::1", "fd00::1", "fe80::1", "::ffff:192.168.1.1", "::ffff:10.0.0.1"] {
            assert!(is_private_ip(ip.parse::<IpAddr>().unwrap()), "{ip} should be private");
        }
    }

    #[test]
    fn public_ipv6() {
        for ip in ["2001:4860:4860::8888", "2400:3200::1", "2606:4700:4700::1111", "::ffff:8.8.8.8"] {
            assert!(!is_private_ip(ip.parse::<IpAddr>().unwrap()), "{ip} should be public");
        }
    }

    #[test]
    fn scheme_validation() {
        assert_eq!(validate_url_scheme_and_host("http://example.com").unwrap(), "example.com");
        assert_eq!(validate_url_scheme_and_host("https://example.com:8443/x").unwrap(), "example.com");
        assert!(validate_url_scheme_and_host("file:///etc/passwd").is_err());
        assert!(validate_url_scheme_and_host("gopher://example.com").is_err());
        assert!(validate_url_scheme_and_host("http://").is_err());
    }

    #[test]
    fn mapped_ipv4_private() {
        assert!(is_private_ip("::ffff:10.1.2.3".parse().unwrap()));
        assert!(!is_private_ip("::ffff:8.8.8.8".parse().unwrap()));
    }
}
