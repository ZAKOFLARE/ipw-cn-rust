//! Whois 查询（对齐 Go 原版 webtest/whois.go，Rust 手写实现）
//!
//! 流程：内置 TLD 映射 → IANA 查询服务器地址 → 自定义 DNS 并行解析 A/AAAA（SSRF 过滤）
//! → Happy Eyeballs（v4 立即 + v6 延迟 150ms）→ 43 端口查询 → 结构化解析

use super::dns::{DnsConfig, resolve_a, resolve_aaaa};
use crate::ssrf;
use serde::Serialize;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinSet;

/// Happy Eyeballs v6 启动延迟（对齐 Go 常量）
const HAPPY_EYEBALLS_V6_DELAY: Duration = Duration::from_millis(150);
/// 单 IP 连接 + 读写超时上限（对齐 Go 常量）
const WHOIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// IANA whois 服务器
const IANA_SERVER: &str = "whois.iana.org";

/// Whois 查询结果（对齐 WhoisResult）
#[derive(Debug, Clone, Default, Serialize)]
pub struct WhoisResult {
    #[serde(rename = "domain")]
    pub domain: String,
    #[serde(rename = "status")]
    pub status: Vec<String>,
    #[serde(rename = "registrar")]
    pub registrar: WhoisRegistrar,
    #[serde(rename = "registrant")]
    pub registrant: WhoisContact,
    #[serde(rename = "technical")]
    pub technical: WhoisContact,
    #[serde(rename = "abuseContact")]
    pub abuse_contact: WhoisContact,
    #[serde(rename = "dates")]
    pub dates: WhoisDates,
    #[serde(rename = "nameservers")]
    pub name_servers: Vec<String>,
    #[serde(rename = "whoisServer")]
    pub whois_server: String,
    #[serde(rename = "raw")]
    pub raw: String,
    #[serde(rename = "error")]
    pub error: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WhoisRegistrar {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "ianaId")]
    pub iana_id: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WhoisContact {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "org")]
    pub org: String,
    #[serde(rename = "phone")]
    pub phone: String,
    #[serde(rename = "email")]
    pub email: String,
    #[serde(rename = "province")]
    pub province: String,
    #[serde(rename = "contactUri")]
    pub contact_uri: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WhoisDates {
    #[serde(rename = "registration")]
    pub registration: String,
    #[serde(rename = "expiration")]
    pub expiration: String,
    #[serde(rename = "lastChanged")]
    pub last_changed: String,
}

/// 内置 TLD → whois 服务器映射（对齐 Go tldWhoisServers）
fn tld_whois_servers() -> HashMap<&'static str, &'static str> {
    [
        ("com", "whois.verisign-grs.com"),
        ("net", "whois.verisign-grs.com"),
        ("org", "whois.pir.org"),
        ("info", "whois.afilias.net"),
        ("biz", "whois.neulevel.biz"),
        ("name", "whois.nic.name"),
        ("pro", "whois.registrypro.pro"),
        ("io", "whois.nic.io"),
        ("co", "whois.nic.co"),
        ("me", "whois.nic.me"),
        ("cc", "whois.nic.cc"),
        ("tv", "whois.nic.tv"),
        ("top", "whois.nic.top"),
        ("xyz", "whois.nic.xyz"),
        ("club", "whois.nic.club"),
        ("online", "whois.nic.online"),
        ("site", "whois.nic.site"),
        ("store", "whois.nic.store"),
        ("shop", "whois.nic.shop"),
        ("app", "whois.nic.google"),
        ("dev", "whois.nic.google"),
        ("tech", "whois.nic.tech"),
        ("cn", "whois.cnnic.cn"),
        ("wang", "whois.gtld.knet.cn"),
        ("ren", "whois.renren.us"),
    ]
    .into_iter()
    .collect()
}

/// 提取域名后缀（对齐 getExtension）
fn get_extension(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 1].to_string()
    } else {
        domain.to_string()
    }
}

/// 解析 whois 服务器：内置映射优先，无命中查 IANA（对齐 resolveWhoisServer）
async fn resolve_whois_server(ext: &str, _dns: &DnsConfig) -> Result<String, String> {
    let map = tld_whois_servers();
    if let Some(server) = map.get(ext) {
        if !server.is_empty() {
            return Ok(server.to_string());
        }
    }

    // IANA 查询
    let raw = raw_query(format!(".{ext}").as_str(), IANA_SERVER, "43").await?;
    let server = extract_whois_server(&raw);
    if server.is_empty() {
        return Err(format!("no whois server found in IANA response for .{ext}"));
    }
    Ok(server)
}

/// 从 IANA 响应提取 whois 服务器地址（对齐 extractWhoisServer）
fn extract_whois_server(data: &str) -> String {
    for token in ["whois: ", "Whois: "] {
        if let Some(idx) = data.find(token) {
            let start = idx + token.len();
            let rest = &data[start..];
            let end = rest.find('\n').unwrap_or(rest.len());
            let server = rest[..end]
                .trim()
                .trim_start_matches("http://")
                .trim_start_matches("https://")
                .trim_start_matches("whois://")
                .trim_end_matches('/');
            return server.to_string();
        }
    }
    String::new()
}

/// 过滤 SSRF 私网 IP（对齐 filterPublicIPs）
fn filter_public_ips(ips: Vec<String>) -> Vec<String> {
    if !ssrf::enabled() {
        return ips;
    }
    ips.into_iter()
        .filter(|s| match s.parse::<std::net::IpAddr>() {
            Ok(ip) => !ssrf::is_private_ip(ip),
            Err(_) => true,
        })
        .collect()
}

/// 并行解析 A + AAAA 并过滤私网（对齐 resolveWhoisServerIPs）
async fn resolve_server_ips(server: &str, dns: &DnsConfig) -> Result<(Vec<String>, Vec<String>), String> {
    let (a, aaaa) = tokio::join!(resolve_a(server, dns), resolve_aaaa(server, dns));

    if a.record.is_empty() && aaaa.record.is_empty() {
        return Err(format!("both A and AAAA DNS lookup failed for {server}"));
    }

    let v4 = filter_public_ips(a.record);
    let v6 = filter_public_ips(aaaa.record);

    if v4.is_empty() && v6.is_empty() {
        return Err(format!("no reachable public IPs for {server} after SSRF filter"));
    }
    Ok((v4, v6))
}

/// 单 IP whois 查询（对齐 rawWhoisQueryCtx 简化版：timeout 取代 ctx）
async fn raw_query(domain: &str, server: &str, port: &str) -> Result<String, String> {
    let addr = format!("{server}:{port}");
    let connect = async {
        let addr: SocketAddr = addr
            .parse()
            .map_err(|e| format!("invalid address {addr}: {e}"))?;
        TcpStream::connect(addr).await.map_err(|e| e.to_string())
    };

    let mut stream = tokio::time::timeout(WHOIS_CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| format!("dial tcp {addr}: i/o timeout"))??;

    // 写查询
    stream
        .write_all(format!("{domain}\r\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;

    // 循环读取：EOF / 连接关闭 / 读超时均视为结束
    // 对齐 Go likexian/whois：whois 服务器常不主动关闭连接，靠读超时（deadline）返回已读数据
    let read = async {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 8192];
        let mut err_count = 0u32;
        loop {
            match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
                Err(_) => return Ok::<Vec<u8>, String>(out), // 读超时 = 数据已收完
                Ok(Ok(0)) => return Ok(out),                 // EOF
                Ok(Ok(n)) => {
                    out.extend_from_slice(&buf[..n]);
                    err_count = 0;
                }
                Ok(Err(_)) => {
                    // RST 等连接异常：重试读取缓冲中残留数据
                    err_count += 1;
                    if err_count >= 3 || out.is_empty() {
                        if out.is_empty() {
                            return Err("read failed".to_string());
                        }
                        return Ok(out);
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
            if out.len() >= 65536 {
                return Ok(out);
            }
        }
    };

    let out = tokio::time::timeout(WHOIS_CONNECT_TIMEOUT + Duration::from_secs(5), read)
        .await
        .map_err(|_| "read timeout".to_string())??;

    if out.is_empty() {
        Err("empty whois response".to_string())
    } else {
        Ok(String::from_utf8_lossy(&out).to_string())
    }
}

/// Happy Eyeballs 双栈竞争查询（对齐 happyEyeballsWhoisQuery）
/// v4 立即启动；v6 延迟 150ms；第一个成功返回；JoinSet drop 时中止其余任务
async fn happy_eyeballs_query(
    domain: &str,
    v4: Vec<String>,
    v6: Vec<String>,
    port: &str,
) -> Result<String, String> {
    if v4.is_empty() && v6.is_empty() {
        return Err("no IPs available for WHOIS query".to_string());
    }

    let mut set = JoinSet::new();

    for ip in &v4 {
        let ip = ip.clone();
        let domain = domain.to_string();
        let port = port.to_string();
        set.spawn(async move { raw_query(&domain, &ip, &port).await });
    }
    for ip in &v6 {
        let ip = ip.clone();
        let domain = domain.to_string();
        let port = port.to_string();
        set.spawn(async move {
            tokio::time::sleep(HAPPY_EYEBALLS_V6_DELAY).await;
            raw_query(&domain, &ip, &port).await
        });
    }

    let mut last_err: Option<String> = None;
    while let Some(res) = set.join_next().await {
        match res {
            Ok(Ok(raw)) => return Ok(raw),
            Ok(Err(e)) => last_err = Some(e),
            Err(e) => last_err = Some(e.to_string()),
        }
    }

    Err(last_err.unwrap_or_else(|| "all WHOIS connection attempts failed".to_string()))
}

/// 完整 whois 查询（对齐 QueryWhois + whoisRetryWithFallback）
pub async fn query_whois(domain: &str, dns: &DnsConfig) -> WhoisResult {
    let ext = get_extension(domain);

    let server = match resolve_whois_server(&ext, dns).await {
        Ok(s) => s,
        Err(e) => {
            return WhoisResult {
                domain: domain.to_uppercase(),
                error: e,
                ..Default::default()
            };
        }
    };

    let (v4, v6) = match resolve_server_ips(&server, dns).await {
        Ok(r) => r,
        Err(e) => {
            return WhoisResult {
                domain: domain.to_uppercase(),
                error: e,
                ..Default::default()
            };
        }
    };

    let raw = match happy_eyeballs_query(domain, v4, v6, "43").await {
        Ok(raw) => raw,
        Err(e) => {
            return WhoisResult {
                domain: domain.to_uppercase(),
                error: e,
                ..Default::default()
            };
        }
    };

    let mut result = parse_whois_result(domain, &raw);
    // 对齐 Go：WhoisServer 只来自响应解析（"whois server"/"registrar whois server"），不覆盖为查询服务器
    result.error = String::new();
    result
}

/// 解析原始 whois 响应为结构化数据（对齐 parseWhoisResult，手写实现近似 whois-parser）
pub fn parse_whois_result(domain: &str, raw: &str) -> WhoisResult {
    let mut result = WhoisResult {
        domain: domain.to_uppercase(),
        raw: raw.to_string(),
        ..Default::default()
    };

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once(':') else { continue };
        let key = key.trim().to_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        match key.as_str() {
            // 对齐 whois-parser fixDomainStatus：先逗号拆分，再取首 token（"not delegated" 特例）
            "domain status" | "status" | "registration status" | "query status" | "state" => {
                for item in value.split(',') {
                    let item = item.trim();
                    if item.is_empty() {
                        continue;
                    }
                    let mut names = item.split_whitespace();
                    let first = names.next().unwrap_or("");
                    let status = if first.eq_ignore_ascii_case("not")
                        && names.next().is_some_and(|n| n.eq_ignore_ascii_case("delegated"))
                    {
                        "not delegated".to_string()
                    } else {
                        first.to_string()
                    };
                    result.status.push(status);
                }
            }
            // 对齐 whois-parser keyRule："registrar whois server" 也映射 whois_server
            "whois server" | "registrar whois server" => {
                if result.whois_server.is_empty() {
                    result.whois_server = value.to_string();
                }
            }
            "registrar" | "sponsoring registrar" => {
                if result.registrar.name.is_empty() {
                    result.registrar.name = value.to_string();
                }
            }
            // 日期（近似 whois-parser 的 knownFields）
            k if is_created_key(k) => set_once(&mut result.dates.registration, value),
            k if is_expired_key(k) => set_once(&mut result.dates.expiration, value),
            k if is_updated_key(k) => set_once(&mut result.dates.last_changed, value),
            _ => {}
        }

        // name server（对齐 whois-parser fixNameServers：逗号拆分、首 token、小写、去尾点）
        if key.starts_with("name server") || key.starts_with("nameserver") {
            for item in value.split(',') {
                let item = item.trim();
                if item.is_empty() {
                    continue;
                }
                let first = item.split_whitespace().next().unwrap_or("");
                result
                    .name_servers
                    .push(first.trim_end_matches('.').to_lowercase());
            }
            continue;
        }

        // 联系人字段
        if key.starts_with("registrant") {
            if let Some(f) = contact_subfield(&key["registrant".len()..]) {
                apply_contact_field(&mut result.registrant, f, value);
            }
        } else if key.starts_with("technical") || key.starts_with("tech") {
            let sub = key.trim_start_matches("technical").trim_start_matches("tech");
            if let Some(f) = contact_subfield(sub) {
                apply_contact_field(&mut result.technical, f, value);
            }
        }
    }

    // Abuse 联系人（从原始文本提取）
    if let Some(abuse) = extract_abuse_contact(raw) {
        result.abuse_contact = abuse;
    }

    // Registrar IANA ID
    if !result.registrar.name.is_empty() {
        result.registrar.iana_id = extract_iana_id(raw);
    }

    result
}

fn is_created_key(k: &str) -> bool {
    matches!(
        k,
        "creation date"
            | "created date"
            | "created"
            | "registration date"
            | "registered date"
            | "registered"
            | "created on"
            | "date created"
            | "domain registration date"
            | "registration time"
    )
}

fn is_expired_key(k: &str) -> bool {
    matches!(
        k,
        "registry expiry date"
            | "expiration date"
            | "expiry date"
            | "paid-till"
            | "expire date"
            | "expires"
            | "registration expiration date"
            | "domain expiration date"
    )
}

fn is_updated_key(k: &str) -> bool {
    matches!(
        k,
        "updated date"
            | "last updated"
            | "updated"
            | "last modified"
            | "last updated date"
            | "updated on"
            | "modified"
            | "last update"
    )
}

fn set_once(target: &mut String, value: &str) {
    if target.is_empty() {
        *target = value.to_string();
    }
}

/// 判断联系人子字段（去掉 registrant/technical 前缀后的部分）
fn contact_subfield(sub: &str) -> Option<ContactField> {
    let sub = sub.trim();
    if sub.is_empty() || sub == "id" || sub == "contact id" {
        return None;
    }
    Some(match sub {
        "name" | "contact name" | "name in chinese" => ContactField::Name,
        "organization" | "org" | "registrant organization" | "organization in chinese" => {
            ContactField::Org
        }
        "email" | "contact email" => ContactField::Email,
        "phone" | "contact phone" | "telephone" => ContactField::Phone,
        "province" | "state" | "region" | "province in chinese" => ContactField::Province,
        "referral url" | "url" => ContactField::ContactUri,
        _ => return None,
    })
}

#[derive(Clone, Copy, PartialEq)]
enum ContactField {
    Name,
    Org,
    Email,
    Phone,
    Province,
    ContactUri,
}

fn apply_contact_field(contact: &mut WhoisContact, field: ContactField, value: &str) {
    match field {
        ContactField::Name => contact.name = value.to_string(),
        ContactField::Org => contact.org = value.to_string(),
        ContactField::Email => contact.email = value.to_string(),
        ContactField::Phone => contact.phone = value.to_string(),
        ContactField::Province => contact.province = value.to_string(),
        ContactField::ContactUri => contact.contact_uri = value.to_string(),
    }
}

/// 提取 Abuse 联系人（对齐 extractAbuseContactFromRaw）
fn extract_abuse_contact(raw: &str) -> Option<WhoisContact> {
    let email_re = regex::Regex::new(
        r"(?i)^\s*(?:Registrar\s+Abuse\s+Contact\s+Email|Abuse\s+(?:Contact\s+)?Email)\s*[:=]\s*(.+?)\s*$",
    )
    .unwrap();
    let phone_re = regex::Regex::new(
        r"(?i)^\s*(?:Registrar\s+Abuse\s+Contact\s+Phone|Abuse\s+(?:Contact\s+)?Phone)\s*[:=]\s*(.+?)\s*$",
    )
    .unwrap();

    let mut abuse = WhoisContact::default();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(caps) = email_re.captures(line) {
            if let Some(m) = caps.get(1) {
                abuse.email = m.as_str().trim().to_string();
            }
        }
        if let Some(caps) = phone_re.captures(line) {
            if let Some(m) = caps.get(1) {
                abuse.phone = m.as_str().trim().to_string();
            }
        }
    }

    if !is_empty_contact(&abuse) {
        Some(abuse)
    } else {
        None
    }
}

fn is_empty_contact(c: &WhoisContact) -> bool {
    c.name.is_empty()
        && c.org.is_empty()
        && c.phone.is_empty()
        && c.email.is_empty()
        && c.province.is_empty()
        && c.contact_uri.is_empty()
}

/// 提取 Registrar IANA ID（对齐 extractIanaIdFromRaw）
fn extract_iana_id(raw: &str) -> String {
    let re = regex::Regex::new(r"(?i)^\s*Registrar\s+IANA\s+ID\s*[:=]\s*(\S+)").unwrap();
    for line in raw.lines() {
        let line = line.trim();
        if let Some(caps) = re.captures(line) {
            if let Some(m) = caps.get(1) {
                return m.as_str().to_string();
            }
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extension_extraction() {
        assert_eq!(get_extension("example.com"), "com");
        assert_eq!(get_extension("a.b.co.uk"), "uk");
        assert_eq!(get_extension("localhost"), "localhost");
    }

    #[test]
    fn iana_server_extraction() {
        let raw = "whois: whois.verisign-grs.com\n\nDomain Name: COM\n";
        assert_eq!(extract_whois_server(raw), "whois.verisign-grs.com");
        let raw = "refer: whois.verisign-grs.com\n";
        assert_eq!(extract_whois_server(raw), "");
    }

    #[test]
    fn parse_basic_com() {
        let raw = r#"   Domain Name: EXAMPLE.COM
   Registry Domain ID: 123
   Registrar: Example Registrar, Inc.
   Registrar IANA ID: 1234
   Registrar Abuse Contact Email: abuse@example.com
   Registrar Abuse Contact Phone: +1.1234567890
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Registry Expiry Date: 2027-08-14T04:00:00Z
   Creation Date: 2020-08-14T04:00:00Z
   Updated Date: 2026-07-01T12:00:00Z
   Name Server: NS1.EXAMPLE.COM
   Name Server: NS2.EXAMPLE.COM
   Registrant Name: John Doe
   Registrant Organization: Example Corp
   Registrant Email: john@example.com
   Registrant Phone: +1.5551234567
   Technical Name: Tech Admin
   Technical Email: tech@example.com
"#;
        let result = parse_whois_result("example.com", raw);
        assert_eq!(result.domain, "EXAMPLE.COM");
        assert_eq!(result.registrar.name, "Example Registrar, Inc.");
        assert_eq!(result.registrar.iana_id, "1234");
        assert_eq!(result.status.len(), 2);
        assert!(result.status[0].contains("clientDeleteProhibited"));
        assert_eq!(result.dates.expiration, "2027-08-14T04:00:00Z");
        assert_eq!(result.dates.registration, "2020-08-14T04:00:00Z");
        assert_eq!(result.dates.last_changed, "2026-07-01T12:00:00Z");
        assert_eq!(result.name_servers, vec!["ns1.example.com", "ns2.example.com"]);
        assert_eq!(result.registrant.name, "John Doe");
        assert_eq!(result.registrant.org, "Example Corp");
        assert_eq!(result.registrant.email, "john@example.com");
        assert_eq!(result.abuse_contact.email, "abuse@example.com");
        assert_eq!(result.abuse_contact.phone, "+1.1234567890");
    }

    #[tokio::test]
    async fn real_whois_query() {
        let dns = DnsConfig::default();
        let result = query_whois("baidu.com", &dns).await;
        assert!(result.error.is_empty(), "error: {}", result.error);
        assert!(!result.raw.is_empty());
        assert_eq!(result.domain, "BAIDU.COM");
    }
}
