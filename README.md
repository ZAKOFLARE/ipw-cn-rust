原始README.MD请前往 https://github.com/nomdn/ipw-cn 查看
---

## 项目范围

### 我们不应该做的

| 模块 | 说明 |
|------|------|
| `ipdb/`（searchip.go / ipdb.go） | IP 定位与 ASN 查询依赖的 IP 数据库链路，整体排除 |
| `/v1/location` `/v1/location/:ip` `/v1/asn/:ip` | 后端不提供这三个接口 |
| `lemon-getip` / `edgeone-getip` | Cloudflare / EdgeOne 边缘 IP 查询服务，前端范畴 |
| `edgeone/` | EdgeOne 边缘函数版本后端，不在本次重构范围 |
| `frontend-ssr/` | Nuxt 前端，不动 |
| `webtest/whois.go` 中的 `QueryASNWhois` | ASN whois 是配套 IP→ASN 查询的，一并排除 |

### 已完成的(后端)

| 路由 | 说明 |
|------|------|
| `GET /` | 健康检查 |
| `GET /v1/detail/*url` | 网站检测：HTTP(S) 状态码、DNS/TCP/HTTP/首字节/总耗时、页面大小、下载速度、HTTPS 失败回退 HTTP |
| `GET /v1/ssl/*url` | SSL 证书：有效期、颁发者、TLS 握手耗时、HTTP 版本 |
| `GET /v1/speed/:version/*url` | 网站测速：v4/v6/dual 单栈，detail 的扩展 + 响应头 + message |
| `GET /v1/tcping/:ip?port=&count=` | TCP 连接测试，双栈并行，多次统计（min/avg/max/loss） |
| `GET /v1/dns/:type/*domain` | DNS 查询：A/AAAA/CNAME/MX/TXT/NS/SRV/PTR/CAA/all |
| `GET /v1/dnssec/:domain` | DNSSEC 验证：DNSKEY/RRSIG/DS 信任链 |
| `GET /v1/whois/:domain` | Whois 查询：注册信息解析 + Abuse 提取 + 原始响应 |

### 已完成的(中间层)

- 纯转发代理，路由 `/{prefix}/{backendID}/{apiType}/{raw...}`，`prefix ∈ {v1, middleware}`
- `apiType` 全量保留 8 种转发：`whois / dns / location / ssl / asn / dnssec / detail / tcping / speed`
  （location/asn 仅是转发到上游 IP 数据 API，中间层本身不实现 IP 库逻辑，属"装"的职责）
- 上游状态码与 body 原样透传；网络层错误返回 502；apiKeys → `Authorization: Bearer`

---
## Cargo Workspace 总览

```
ipw-rs/
├── Cargo.toml                      # [workspace] members = ["crates/*"]
├── .gitignore
├── Dockerfile.backend              # 后端镜像
├── Dockerfile.middleware           # 中间层镜像
│
├── crates/
│   ├── ipw-backend/                # 自托管后端（独立二进制）
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs             # 入口：加载配置 → 初始化客户端 → 起服务
│   │       ├── config.rs           # setting.json + 环境变量 + 远端配置
│   │       ├── http.rs             # 双栈 HTTP 客户端 + SSRF 拦截 + 时间插桩
│   │       ├── ssrf.rs             # 私有 IP 判定 + 重定向校验（手写，零依赖）
│   │       ├── cache.rs            # TTL 缓存 + 单飞防击穿
│   │       ├── auth.rs             # access_token Bearer 校验
│   │       └── api/
│   │           ├── mod.rs          # 路由注册 + CORS + 统一错误包装
│   │           ├── detail.rs       # /v1/detail
│   │           ├── ssl.rs          # /v1/ssl
│   │           ├── speed.rs        # /v1/speed
│   │           ├── tcping.rs       # /v1/tcping
│   │           ├── dns.rs          # /v1/dns
│   │           ├── dnssec.rs       # /v1/dnssec
│   │           └── whois.rs        # /v1/whois
│   │       └── webtest/
│   │           ├── dns.rs          # DNS 查询（UDP + DoH）
│   │           ├── dnssec.rs       # DNSSEC 验证
│   │           ├── tcping.rs       # TCPing 统计
│   │           └── whois.rs        # whois 查询 + 解析（手写）
│   │
│   └── ipw-middleware/             # 转发中间件（独立二进制）
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs             # 入口
│           ├── config.rs           # 平铺 setting.json + 环境变量覆盖
│           └── forward.rs          # 路由解析 + 上游转发 + CORS
```
<img width="809" height="809" alt="custom-ava" src="https://github.com/user-attachments/assets/f48a9a9f-5c86-4f02-86e9-9715516c7591" />
