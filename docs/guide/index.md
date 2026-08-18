# 部署指南

### 本章节将一步步指导您自部署柠檬味IPW

Lemon IPW 采用前后端分离架构，前端、后端、独立中间件可各自独立部署，并按需组合：

```
┌─────────────────┐      /v1/*      ┌──────────────────┐
│  SSR 前端        │ ──────────────▶ │ 后端 / 独立中间件  │
│ (Cloudflare      │   /middleware/* │ (自托管 / EdgeOne)│
│  Workers 等)     │ ──────────────▶ │  多节点候选重试    │
└─────────────────┘                 └──────────────────┘
```

## 前端

前端是全项目的核心，负责数据可视化和接口调用，部署到 Cloudflare Workers（也可部署到其他符合 Serverless 标准的平台）。

[▶ 前端部署](/guide/deploy-frontend)

## 后端（自托管）

Go 后端提供全部检测 API（IP 归属地 / ASN / SSL / DNS / DNSSEC / Whois / TCPing / 测速 / 截图等），可 Docker 部署或直接运行二进制：

```bash
# 方式一：Docker
docker build -t lemon-ipw .
docker run -p 8080:8080 -v $(pwd)/setting.json:/app/setting.json lemon-ipw

# 方式二：直接运行
go run main.go   # 首次启动自动下载 IP 数据库（约 200MB），之后每 24h 自动更新
```

配置项见根目录 `setting.json` 及环境变量表（`PORT` / `CORS` / `BLOCK_PRIVATE_IPS` / `DNS_SERVER` 等）。

## 独立中间件（middleware-go）

转发中间件，供前端在多个上游节点之间做候选重试，可独立部署：

```bash
cd middleware-go
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o middleware-go-linux-arm64 .
./middleware-go-linux-arm64          # 运行（可用 SETTING_FILE 指定配置路径）
./middleware-go-linux-arm64 --version  # 查看版本
```

所有配置可通过环境变量覆盖（`API_BASE_URLS` / `IP_LOCATION_APIS` / `CORS` / `APIKEYS` 等，数组/对象用 JSON 字符串），配置优先级：**环境变量 > setting.json > 默认值**。

## 部署平台

本项目支持**一切符合 Serverless 标准的部署平台**，同时也支持容器 / 二进制自托管：

| 组件 | 可部署目标 |
|------|-----------|
| SSR 前端 | Cloudflare Workers、EdgeOne Pages 及任意 Serverless 平台 |
| 后端（自托管） | Docker / 任意容器或裸机 |
| 独立中间件 | 常规服务 / Serverless 函数 |
| 边缘后端 | EdgeOne Pages（`edgeone/`、`edgeone-getip/`） |
| IP 查询服务 | Cloudflare Workers（`lemon-getip/`，Hono） |

## CI/CD

仓库内置 GitHub Actions 流水线，push 到 `main` 时按改动路径自动部署：

| 工作流 | 部署目标 |
|--------|----------|
| `frontend-ssr.yml` | SSR 前端 → Cloudflare Workers |
| `workers.yml` | `lemon-getip/` → Cloudflare Workers |
| `edgeone-backend.yml` | `edgeone/` → EdgeOne Pages |
| `edgeone-getip.yml` | `edgeone-getip/` → EdgeOne Pages |
| `build_and_release.yml` | 后端多平台构建与发布 |
