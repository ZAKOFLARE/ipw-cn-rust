# 前端部署

前端（`frontend-ssr/`）是全项目的核心，负责数据可视化与接口调用。基于 **Nuxt 4 SSR** 构建，部署到 **Cloudflare Workers**（nitro `cloudflare_module` preset）。

## 架构与部署目标

| 项 | 说明 |
|----|------|
| 技术栈 | Nuxt 4 + Vue 3 + Element Plus + VueUse |
| 运行时 | Node.js 22（见 `.node-version`）、包管理器 pnpm 10 |
| 构建产物 | `.output/server/index.mjs` + `.output/public/`（静态资源） |
| 部署目标 | Cloudflare Workers（SSR），也可部署到其他符合 Serverless 标准的平台 |
| 部署配置 | `frontend-ssr/wrangler.jsonc` |

## 准备工作

```bash
# 1. 进入前端目录
cd frontend-ssr

# 2. 安装依赖（需要 Node 22 + pnpm 10）
pnpm install

# 3. 本地开发
pnpm dev
```

## 配置说明

前端所有配置集中在 `frontend-ssr/config/index.ts`：

| 配置项 | 说明 |
|--------|------|
| `siteUrl` | 站点对外地址 |
| `siteName` | 站点名称（页面标题 / 描述 / 页脚品牌） |
| `apiBaseUrls` | 后端上游节点列表（whois / ssl / detail） |
| `IPLocationAPIs` | IP 归属地 / ASN 上游节点列表 |
| `TCPing` / `SpeedTest` / `NSLookup` | 对应功能的多节点候选（DualStack / IPv4 / IPv6） |
| `Middleware` | 外部独立中间件 base URL 列表，`/middleware/*` 请求依次尝试、失败重试下一个 |
| `EnableInternalMiddleware` | 是否启用前端内置中间件（本地转发，作为候选列表最后一位兜底），默认 `true` |
| `v4OnlyAPI` / `v6OnlyAPI` / `DualStackAPI` | Worker IP 查询接口 |
| `umamiHost` 等 | Umami 统计配置 |
| `ICP` / `GongAn` | 网站备案号（页脚展示） |
| `noindex` | 是否禁止搜索引擎索引 |

> 生产环境建议通过构建时的环境变量或部署平台配置覆盖敏感项，不要把密钥写进 `config/index.ts` 提交到仓库。

## 构建与部署

### 本地构建

```bash
# 构建（默认 preset 为 cloudflare_module，可由 NITRO_PRESET 覆盖）
pnpm build

# 本地预览（构建 + wrangler dev）
pnpm preview
```

### 部署到 Cloudflare Workers

```bash
# 构建 + 发布
pnpm deploy   # 等价于 pnpm build && wrangler deploy
```

部署前需要配置 wrangler 认证（二选一）：

```bash
# 方式一：环境变量（CI 中使用）
export CLOUDFLARE_API_TOKEN=your_api_token
export CLOUDFLARE_ACCOUNT_ID=your_account_id

# 方式二：wrangler login（本地交互登录）
npx wrangler login
```

`wrangler.jsonc` 关键配置：

```jsonc
{
  "name": "ipw-cn",                     // Worker 名称
  "main": "./.output/server/index.mjs", // SSR 入口
  "assets": { "binding": "ASSETS", "directory": "./.output/public/" },
  "compatibility_flags": ["nodejs_compat"]  // 需要 Node.js 兼容层
}
```

## 一键部署到 EdgeOne Makers

腾讯云 EdgeOne 原生支持 Nuxt，点击下方按钮即可通过 **EdgeOne Makers** 一键部署本前端（无需手动配置构建）：

[![使用 EdgeOne Makers 部署](https://cdnstatic.tencentcs.com/edgeone/pages/deploy.svg)](https://console.cloud.tencent.com/edgeone/makers/new?repository-url=https%3A%2F%2Fgithub.com%2Fnomdn%2Fipw-cn&root-directory=frontend-ssr&install-command=pnpm%20install&build-command=pnpm%20run%20build&output-directory=.output)

按钮已预置以下参数：

| 参数 | 值 | 说明 |
|------|-----|------|
| `repository-url` | `https://github.com/nomdn/ipw-cn` | GitHub 仓库地址 |
| `root-directory` | `frontend-ssr` | 构建根目录 |
| `install-command` | `pnpm install` | 依赖安装命令 |
| `build-command` | `pnpm run build` | 构建命令（Nuxt 默认 SSR 构建） |
| `output-directory` | `.output` | 构建产物输出目录（Nitro SSR 产物） |

> 说明：EdgeOne Makers 原生支持 Nuxt 部署，**SSR / SSG / ISR(SWR) / 中间件 / 流式传输**均支持（Nuxt 3.16+，推荐 Nuxt 4），按钮默认以 **SSR** 方式构建。如需纯静态部署，可将 `build-command` 改为 `pnpm run generate`、`output-directory` 改为 `.output/public`。

## CI/CD 自动部署

仓库内置工作流 `.github/workflows/frontend-ssr.yml`：

- **触发条件**：push 到 `main` 且改动路径为 `frontend-ssr/**`；或手动 `workflow_dispatch`
- **步骤**：checkout → Node 22 + pnpm 10 → `pnpm install` → `pnpm run deploy --keep-vars`
- **所需 Secrets**：`CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID`
- **注意**：工作流设置了 `NITRO_PRESET: cloudflare_module`，如本地构建异常可参考此值

## 常见问题

- **构建报 preset 相关错误**：确认构建环境变量 `NITRO_PRESET=cloudflare_module`。
- **本地 `pnpm preview` 与线上行为不一致**：预览使用 `wrangler dev` 模拟 Workers 运行时，请确保 `nodejs_compat` 兼容标志已启用。
- **部署后接口 403 / 跨域**：检查后端 `cors` 配置（独立中间件见 `middleware-go/setting.json` 的 `cors` 字段，逗号分隔允许域名）；服务端转发请求不带 `Origin`，浏览器直接调用才受 CORS 限制。

## 其他部署目标

本项目前端同样支持部署到其他**符合 Serverless 标准**的平台（无状态、事件驱动、自动扩缩容），如 EdgeOne Pages 等。只需按目标平台的约定调整 nitro preset（例如 `nitro preset` 切换）并配置对应产物入口即可。
