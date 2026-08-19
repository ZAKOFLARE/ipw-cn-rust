//! DNSSEC 验证（对齐 Go 原版 webtest/dnssec.go）
//!
//! 流程（对齐 ResolveDNSSEC）：
//! 1. 查询 DNSKEY 记录（带 DO 位），获取密钥列表
//! 2. 查询 A 记录（带 DO 位），获取 A RRset + RRSIG
//! 3. 用 DNSKEY 逐一对 RRSIG 验签（hickory dnssec-ring 验证原语）
//! 4. 查询 DS 记录，检查链式信任

use super::dns::{DnsConfig, query};
use hickory_proto::dnssec::rdata::{DNSSECRData, DNSKEY, RRSIG};
use hickory_proto::dnssec::Verifier;
use hickory_proto::op::{Edns, Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use serde::Serialize;
use std::str::FromStr;
use std::time::Instant;

/// DNSSEC 验证结果（对齐 DNSSECResult）
#[derive(Debug, Clone, Serialize)]
pub struct DnssecResult {
    #[serde(rename = "domain")]
    pub domain: String,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    #[serde(rename = "valid")]
    pub valid: bool,
    #[serde(rename = "has_rrsig")]
    pub has_rrsig: bool,
    #[serde(rename = "has_dnskey")]
    pub has_dnskey: bool,
    #[serde(rename = "has_ds")]
    pub has_ds: bool,
    #[serde(rename = "algorithm")]
    pub algorithm: u8,
    #[serde(rename = "key_tag")]
    pub key_tag: u16,
    #[serde(rename = "signer_name")]
    pub signer_name: String,
    #[serde(rename = "validation")]
    pub validation: String,
    #[serde(rename = "duration")]
    pub duration: f64,
}

/// 构建带 DO 位的查询消息（对齐 SetEdns0(4096, true)）
fn build_query_do(domain: &str, rtype: RecordType) -> Result<Message, String> {
    let name = Name::from_str(domain).map_err(|e| format!("invalid domain {domain}: {e}"))?;
    let mut msg = Message::new();
    msg.set_id(rand_id());
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(true);
    let mut edns = Edns::new();
    edns.set_max_payload(4096);
    edns.set_dnssec_ok(true);
    msg.set_edns(edns);
    msg.add_query(Query::query(name, rtype));
    Ok(msg)
}

fn rand_id() -> u16 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    (nanos & 0xffff) as u16
}

/// 执行 DNSSEC 验证（对齐 ResolveDNSSEC）
pub async fn resolve_dnssec(domain: &str, cfg: &DnsConfig) -> DnssecResult {
    let start = Instant::now();
    let mut result = DnssecResult {
        domain: domain.to_string(),
        enabled: false,
        valid: false,
        has_rrsig: false,
        has_dnskey: false,
        has_ds: false,
        algorithm: 0,
        key_tag: 0,
        signer_name: String::new(),
        validation: String::new(),
        duration: 0.0,
    };

    // 1. 查询 DNSKEY
    let msg_dnskey = match build_query_do(domain, RecordType::DNSKEY) {
        Ok(m) => m,
        Err(e) => {
            result.validation = format!("DNSKEY query failed: {e}");
            result.duration = start.elapsed().as_secs_f64() * 1000.0;
            return result;
        }
    };
    let response_dnskey = query(&msg_dnskey, cfg).await;
    result.duration = start.elapsed().as_secs_f64() * 1000.0;

    let response_dnskey = match response_dnskey {
        Ok(r) => r,
        Err(e) => {
            result.validation = format!("DNSKEY query failed: {e}");
            return result;
        }
    };
    if response_dnskey.response_code() != ResponseCode::NoError {
        result.validation = format!(
            "DNSKEY query failed with Rcode {}",
            u16::from(response_dnskey.response_code())
        );
        return result;
    }

    let mut dnskey_list: Vec<DNSKEY> = Vec::new();
    for ans in response_dnskey.answers() {
        match ans.data() {
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => {
                dnskey_list.push(key.clone());
                result.has_dnskey = true;
            }
            _ => {}
        }
    }

    if let Some(first) = dnskey_list.first() {
        result.key_tag = first.calculate_key_tag().unwrap_or(0);
        result.algorithm = u8::from(first.algorithm());
    }

    // 2. 查询 A 记录（带 DO 位）
    let msg_a = match build_query_do(domain, RecordType::A) {
        Ok(m) => m,
        Err(_) => return result,
    };
    let response_a = query(&msg_a, cfg).await;



    if let Ok(response_a) = response_a {
        if response_a.response_code() == ResponseCode::NoError {
            let mut a_rrset: Vec<Record> = Vec::new();
            let mut rrsig_list: Vec<RRSIG> = Vec::new();

            for ans in response_a.answers() {
                match ans.data() {
                    RData::A(_) => a_rrset.push(ans.clone()),
                    RData::DNSSEC(DNSSECRData::RRSIG(rrsig)) => {
                        rrsig_list.push(rrsig.clone());
                        result.has_rrsig = true;
                    }
                    _ => {}
                }
            }

            // 3. 用 DNSKEY 逐条验证 RRSIG（DNSKEY 实现 Verifier trait）
            // owner name 必须与 RRset 一致（FQDN，hickory 内部为绝对名）
            let owner = a_rrset
                .first()
                .map(|r| r.name().clone())
                .or_else(|| Name::from_str(&format!("{domain}.")).ok());
            for rrsig in &rrsig_list {
                for dnskey in &dnskey_list {
                    let verified = owner.as_ref().map(|name| {
                        dnskey.verify_rrsig(name, DNSClass::IN, rrsig, a_rrset.iter())
                    });
                    if matches!(verified, Some(Ok(()))) {
                        result.enabled = true;
                        result.valid = true;
                        result.algorithm = u8::from(dnskey.algorithm());
                        result.key_tag = dnskey.calculate_key_tag().unwrap_or(0);
                        result.signer_name = rrsig.signer_name().to_string();
                        result.validation = format!(
                            "DNSSEC 验证通过 (算法: {}, KeyTag: {})",
                            u8::from(dnskey.algorithm()),
                            dnskey.calculate_key_tag().unwrap_or(0)
                        );
                        return result;
                    }
                }
            }

            if !rrsig_list.is_empty() && !dnskey_list.is_empty() {
                result.enabled = true;
                result.valid = false;
                result.validation = format!(
                    "RRSIG 验证失败: {} 条 RRSIG, {} 个 DNSKEY，无匹配签名",
                    rrsig_list.len(),
                    dnskey_list.len()
                );
                return result;
            }
        }
    }

    // 4. 查询 DS 记录
    let msg_ds = match build_query_do(domain, RecordType::DS) {
        Ok(m) => m,
        Err(_) => return result,
    };
    if let Ok(response_ds) = query(&msg_ds, cfg).await {
        if response_ds.response_code() == ResponseCode::NoError {
            for ans in response_ds.answers() {
                match ans.data() {
                    RData::DNSSEC(DNSSECRData::DS(_)) => {
                        result.has_ds = true;
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    if result.has_rrsig && result.has_dnskey {
        result.enabled = true;
        result.valid = false;
        result.validation = "存在 RRSIG 和 DNSKEY，但签名验证未通过".to_string();
    } else if result.has_rrsig {
        result.enabled = true;
        result.valid = false;
        result.validation = "存在 RRSIG，但缺少 DNSKEY".to_string();
    } else if result.has_dnskey {
        result.enabled = false;
        result.valid = false;
        result.validation = "存在 DNSKEY，但缺少 RRSIG".to_string();
    } else {
        result.enabled = false;
        result.valid = false;
        result.validation = "未检测到 DNSSEC 记录".to_string();
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dnssec_signed_domain() {
        // cloudflare.com 已启用 DNSSEC
        // 8.8.8.8 支持 DNSSEC；默认 119.28.28.28（腾讯）过滤 RRSIG（Go 原版同样受限）
        let cfg = DnsConfig { server: "8.8.8.8:53".to_string() };
        let result = resolve_dnssec("cloudflare.com", &cfg).await;
        assert!(result.has_dnskey, "should have DNSKEY: {:?}", result.validation);
        assert!(result.has_rrsig, "should have RRSIG: {:?}", result.validation);
    }

    #[tokio::test]
    async fn dnssec_unsigned_domain() {
        // 未启用 DNSSEC 的域名
        let cfg = DnsConfig::default();
        let result = resolve_dnssec("baidu.com", &cfg).await;
        assert!(!result.enabled, "baidu.com should not have DNSSEC: {:?}", result.validation);
    }
}
