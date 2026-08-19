//! 访问令牌校验（对齐 Go 原版 tokenCheck）
//!
//! 未配置 access_token 时不校验（Go: if ACCESS_TOKEN != "" 才挂中间件）。

/// 校验 Authorization 头。token 为空返回 true（不校验）。
pub fn check(auth_header: &str, token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    auth_header == format!("Bearer {token}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_token_skips() {
        assert!(check("", ""));
        assert!(check("Bearer whatever", ""));
    }

    #[test]
    fn token_matches() {
        assert!(check("Bearer secret123", "secret123"));
        assert!(!check("Bearer wrong", "secret123"));
        assert!(!check("", "secret123"));
        assert!(!check("secret123", "secret123")); // 缺 Bearer 前缀
    }
}
