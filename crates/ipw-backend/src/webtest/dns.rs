//! DNS 查询模块（对齐 Go 原版 webtest/dns.go）
//!
//! 双通道自动互备：
//! - dns-server 配置为 URL（http/https）→ 优先 DoH，失败回退 UDP（119.28.28.28:53）
//! - dns-server 配置为 ip:port → 优先 UDP，失败回退 DoH（https://doh.pub/dns-query）
//! - UDP 大响应（truncated）自动切 TCP 重查（对齐 miekg/dns 行为）

use hickory_proto::op::{Message, MessageType, Query, ResponseCode};
use hickory_proto::op::Edns;
use hickory_proto::rr::{Name, RData, RecordType};
use serde::Serialize;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::warn;

/// 默认 UDP DNS 服务器（Go 原版常量）
pub const DEFAULT_UDP_SERVER: &str = "119.28.28.28:53";
/// 默认 DoH 端点（Go 原版常量）
pub const DEFAULT_DOH_ENDPOINT: &str = "https://doh.pub/dns-query";

/// DNS 查询配置（由后端 Setting 提供）
#[derive(Debug, Clone, Default)]
pub struct DnsConfig {
    /// 配置的 dns-server（空 = 未配置）
    pub server: String,
}

/// 统一 DNS 查询结果（对齐 Go DNSResult）
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DnsResult {
    #[serde(rename = "domain")]
    pub domain: String,
    #[serde(rename = "record")]
    pub record: Vec<String>,
    #[serde(rename = "ttl")]
    pub ttl: u32,
    #[serde(rename = "duration")]
    pub duration: f64,
}

impl DnsResult {
    fn empty(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            record: Vec::new(),
            ttl: 0,
            duration: 0.0,
        }
    }
}

/// 全部 DNS 记录查询结果（不含 PTR，对齐 Go DNSFullResult）
#[derive(Debug, Clone, Serialize)]
pub struct DnsFullResult {
    #[serde(rename = "domain")]
    pub domain: String,
    #[serde(rename = "a")]
    pub a: DnsResult,
    #[serde(rename = "aaaa")]
    pub aaaa: DnsResult,
    #[serde(rename = "cname")]
    pub cname: DnsResult,
    #[serde(rename = "mx")]
    pub mx: DnsResult,
    #[serde(rename = "ns")]
    pub ns: DnsResult,
    #[serde(rename = "txt")]
    pub txt: DnsResult,
    #[serde(rename = "srv")]
    pub srv: DnsResult,
    #[serde(rename = "caa")]
    pub caa: DnsResult,
}

/// 构建查询消息
fn build_query(domain: &str, rtype: RecordType) -> Result<Message, String> {
    build_query_edns(domain, rtype, false)
}

/// 构建查询消息；`do_bit` 为 true 时携带 EDNS0(4096, DO)（对齐 Go SetEdns0(4096, true)）
fn build_query_edns(domain: &str, rtype: RecordType, do_bit: bool) -> Result<Message, String> {
    let name = if rtype == RecordType::PTR {
        // PTR 查询需要反向地址（ip → in-addr.arpa / ip6.arpa）
        reverse_addr(domain)?
    } else {
        Name::from_str(domain).map_err(|e| format!("invalid domain {domain}: {e}"))?
    };

    let mut msg = Message::new();
    msg.set_id(rand_id());
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    if do_bit {
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(true);
        msg.set_edns(edns);
    }
    msg.add_query(Query::query(name, rtype));
    Ok(msg)
}

/// IP → 反向解析名称（对齐 dns.ReverseAddr）
fn reverse_addr(ip_str: &str) -> Result<Name, String> {
    let ip: std::net::IpAddr = ip_str
        .parse()
        .map_err(|_| format!("invalid IP address: {ip_str}"))?;
    let mut parts: Vec<String> = Vec::new();
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            for i in (0..4).rev() {
                parts.push(o[i].to_string());
            }
            parts.push("in-addr.arpa".to_string());
        }
        std::net::IpAddr::V6(v6) => {
            // 每个 nibble 一个标签，逆序；补齐 32 nibble
            let mut labels: Vec<String> = Vec::with_capacity(32);
            let bytes = v6.octets();
            let mut nibbles: Vec<char> = Vec::with_capacity(32);
            for b in bytes {
                nibbles.push(char::from_digit((b >> 4) as u32, 16).unwrap());
                nibbles.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
            }
            for c in nibbles.iter().rev() {
                labels.push(c.to_string());
            }
            labels.push("ip6.arpa".to_string());
            parts = labels;
        }
    }
    Name::from_str(&parts.join(".")).map_err(|e| format!("invalid reverse name: {e}"))
}

fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos & 0xffff) as u16
}

/// 统一查询入口：DoH 与 UDP 双通道自动互备（对齐 queryDNS）
pub(crate) async fn query(msg: &Message, cfg: &DnsConfig) -> Result<Message, String> {
    // 空配置回退默认 UDP 服务器（对齐 Go：dnsServer 初始值即 119.28.28.28:53，SetDNSServer 空不覆盖）
    let server = cfg.server.trim();
    let server = if server.is_empty() { DEFAULT_UDP_SERVER } else { server };
    if server.starts_with("http://") || server.starts_with("https://") {
        match query_doh(msg, server).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                warn!(endpoint = server, error = %e, "DoH query failed, falling back to UDP");
                return query_udp(msg, DEFAULT_UDP_SERVER).await;
            }
        }
    }
    match query_udp(msg, server).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            warn!(server = server, error = %e, "UDP query failed, falling back to DoH");
            query_doh(msg, DEFAULT_DOH_ENDPOINT).await
        }
    }
}

/// UDP 查询；truncated 响应自动切 TCP（对齐 miekg/dns Client.Exchange 行为）
async fn query_udp(msg: &Message, server: &str) -> Result<Message, String> {
    let bytes = msg.to_vec().map_err(|e| format!("pack DNS message: {e}"))?;
    let addr: SocketAddr = server
        .parse()
        .map_err(|_| format!("invalid DNS server: {server}"))?;

    let socket = tokio::net::UdpSocket::bind(if addr.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .map_err(|e| format!("bind udp: {e}"))?;

    socket
        .send_to(&bytes, addr)
        .await
        .map_err(|e| format!("udp send: {e}"))?;

    // 5s 超时（对齐 Go dns.Client{Timeout: 5s}）
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        socket.recv_from(&mut buf),
    )
    .await
    .map_err(|_| "DNS query timeout".to_string())?
    .map_err(|e| format!("udp recv: {e}"))?;

    let resp_bytes = buf[..n].to_vec();
    let resp = Message::from_vec(&resp_bytes).map_err(|e| format!("unpack DNS response: {e}"))?;

    // truncated → TCP 重查
    if resp.truncated() {
        return query_tcp(msg, server).await;
    }
    Ok(resp)
}

/// TCP 查询（2 字节长度前缀，对齐 DNS over TCP 协议）
async fn query_tcp(msg: &Message, server: &str) -> Result<Message, String> {
    let bytes = msg.to_vec().map_err(|e| format!("pack DNS message: {e}"))?;
    let addr: SocketAddr = server
        .parse()
        .map_err(|_| format!("invalid DNS server: {server}"))?;

    let mut stream = TcpStream::connect(addr)
        .await
        .map_err(|e| format!("tcp connect {server}: {e}"))?;

    let len = (bytes.len() as u16).to_be_bytes();
    stream
        .write_all(&[len[0], len[1]])
        .await
        .map_err(|e| format!("tcp write len: {e}"))?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|e| format!("tcp write: {e}"))?;

    let mut len_buf = [0u8; 2];
    tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut len_buf))
        .await
        .map_err(|_| "DNS TCP read timeout".to_string())?
        .map_err(|e| format!("tcp read len: {e}"))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    let mut buf = vec![0u8; resp_len];
    tokio::time::timeout(std::time::Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .map_err(|_| "DNS TCP read timeout".to_string())?
        .map_err(|e| format!("tcp read body: {e}"))?;

    Message::from_vec(&buf).map_err(|e| format!("unpack DNS response: {e}"))
}

/// DoH 查询（RFC 8484，POST application/dns-message，对齐 queryDoHMsg）
async fn query_doh(msg: &Message, endpoint: &str) -> Result<Message, String> {
    let bytes = msg.to_vec().map_err(|e| format!("pack DNS message: {e}"))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .map_err(|e| format!("build doh client: {e}"))?;

    let resp = client
        .post(endpoint)
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(bytes)
        .send()
        .await
        .map_err(|e| format!("DoH request failed: {e}"))?;

    if resp.status() != reqwest::StatusCode::OK {
        return Err(format!("DoH API returned status {}", resp.status().as_u16()));
    }
    let body = resp.bytes().await.map_err(|e| format!("read DoH response: {e}"))?;
    Message::from_vec(&body).map_err(|e| format!("unpack DoH response: {e}"))
}

/// 通用记录查询：构造查询 → 发送 → Rcode 检查 → 提取记录（对齐各 ResolveXxxRecord）
/// 查询网络失败或 Rcode 非成功时返回 Err（对齐 Go 的 error 语义）
async fn resolve_records(
    domain: &str,
    rtype: RecordType,
    cfg: &DnsConfig,
) -> Result<DnsResult, String> {
    let start = Instant::now();
    let mut result = DnsResult::empty(domain);

    let msg = match build_query(domain, rtype) {
        Ok(m) => m,
        Err(e) => {
            warn!(domain, error = %e, "invalid query");
            result.duration = start.elapsed().as_secs_f64() * 1000.0;
            return Err(e);
        }
    };

    let response = query(&msg, cfg).await;
    result.duration = start.elapsed().as_secs_f64() * 1000.0;

    let response = match response {
        Ok(r) => r,
        Err(e) => {
            warn!(domain, error = %e, "failed to query DNS");
            return Err(e);
        }
    };

    if response.response_code() != ResponseCode::NoError {
        warn!(domain, rcode = ?response.response_code(), "DNS query failed with Rcode");
        return Err(format!(
            "DNS query failed with Rcode {}",
            u16::from(response.response_code())
        ));
    }

    // TTL 取第一条匹配记录的 TTL（对齐 Go：result.TTL == 0 时取）
    for ans in response.answers() {
        if ans.record_type() != rtype {
            continue;
        }
        // hickory 0.25：data() 直接返回 &RData；RData 变体为单字段结构体，CNAME/NS/PTR 为 Name 别名
        let values: Option<Vec<String>> = match ans.data() {
            RData::A(a) => Some(vec![a.0.to_string()]),
            RData::AAAA(a) => Some(vec![a.0.to_string()]),
            RData::CNAME(n) => Some(vec![n.to_string()]),
            RData::MX(mx) => Some(vec![mx.exchange().to_string()]),
            RData::NS(n) => Some(vec![n.to_string()]),
            RData::TXT(txt) => Some(
                txt.iter()
                    .map(|b| String::from_utf8_lossy(b).to_string())
                    .collect(),
            ),
            RData::SRV(srv) => Some(vec![srv.target().to_string()]),
            RData::PTR(p) => Some(vec![p.to_string()]),
            // miekg/dns 输出 "0 issue letsencrypt.org"（无引号）；hickory Display 带引号，手动拼 Go 格式
            RData::CAA(caa) => Some(vec![format!(
                "{} {} {}",
                caa.flags(),
                caa.tag(),
                String::from_utf8_lossy(caa.raw_value())
            )]),
            _ => None,
        };
        if let Some(vals) = values {
            for v in vals {
                result.record.push(v);
                if result.ttl == 0 {
                    result.ttl = ans.ttl();
                }
            }
        }
    }
    Ok(result)
}

macro_rules! resolve_impl {
    ($name:ident, $result_name:ident, $rtype:expr) => {
        /// Result 版本（查询失败返回 Err，handler 据此返回 500）
        pub async fn $result_name(domain: &str, cfg: &DnsConfig) -> Result<DnsResult, String> {
            resolve_records(domain, $rtype, cfg).await
        }
        /// 吞错误版本（record 为空，tcping/whois 等内部调用使用；允许未接线，对齐 Go 死代码）
        #[allow(dead_code)]
        pub async fn $name(domain: &str, cfg: &DnsConfig) -> DnsResult {
            match resolve_records(domain, $rtype, cfg).await {
                Ok(r) => r,
                Err(e) => {
                    warn!(domain, error = %e, "dns query suppressed");
                    DnsResult::empty(domain)
                }
            }
        }
    };
}

resolve_impl!(resolve_a, resolve_a_result, RecordType::A);
resolve_impl!(resolve_aaaa, resolve_aaaa_result, RecordType::AAAA);
resolve_impl!(resolve_cname, resolve_cname_result, RecordType::CNAME);
resolve_impl!(resolve_mx, resolve_mx_result, RecordType::MX);
resolve_impl!(resolve_ns, resolve_ns_result, RecordType::NS);
resolve_impl!(resolve_txt, resolve_txt_result, RecordType::TXT);
resolve_impl!(resolve_srv, resolve_srv_result, RecordType::SRV);
resolve_impl!(resolve_ptr, resolve_ptr_result, RecordType::PTR);
resolve_impl!(resolve_caa, resolve_caa_result, RecordType::CAA);

/// 全部记录并行查询（不含 PTR，对齐 ResolveARecordllDNSRecords）
///
/// Go 原版该函数为死代码（无调用点），此处保留为库能力，不暴露为 API。
#[allow(dead_code)]
pub async fn resolve_all(domain: &str, cfg: &DnsConfig) -> DnsFullResult {    let (a, aaaa, cname, mx, ns, txt, srv, caa) = tokio::join!(
        resolve_a(domain, cfg),
        resolve_aaaa(domain, cfg),
        resolve_cname(domain, cfg),
        resolve_mx(domain, cfg),
        resolve_ns(domain, cfg),
        resolve_txt(domain, cfg),
        resolve_srv(domain, cfg),
        resolve_caa(domain, cfg),
    );
    DnsFullResult {
        domain: domain.to_string(),
        a,
        aaaa,
        cname,
        mx,
        ns,
        txt,
        srv,
        caa,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reverse_addr_v4() {
        let name = reverse_addr("1.2.3.4").unwrap();
        assert_eq!(name.to_string(), "4.3.2.1.in-addr.arpa");
    }

    #[test]
    fn reverse_addr_v6() {
        // 2001:db8::1 → 1.0.0.0...0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.
        let name = reverse_addr("2001:db8::1").unwrap().to_string();
        assert!(name.starts_with("1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2"));
        assert!(name.ends_with("ip6.arpa"));
    }

    #[test]
    fn reverse_addr_invalid() {
        assert!(reverse_addr("not-an-ip").is_err());
    }

    #[tokio::test]
    async fn real_query_a() {
        let cfg = DnsConfig { server: String::new() };
        let result = resolve_a("www.baidu.com", &cfg).await;
        assert!(!result.record.is_empty(), "record should not be empty: {:?}", result.record);
        assert!(result.duration >= 0.0);
    }
}
