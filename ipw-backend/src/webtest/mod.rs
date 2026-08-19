//! 网络测试工具（对齐 Go 原版 webtest/ 包）
//!
//! - dns：DNS 查询（UDP + DoH 双通道）
//! - tcping：TCP 连接测试
//! - dnssec：DNSSEC 验证（P2）
//! - whois：Whois 查询（P2）

pub mod dns;
pub mod dnssec;
pub mod tcping;
pub mod whois;
