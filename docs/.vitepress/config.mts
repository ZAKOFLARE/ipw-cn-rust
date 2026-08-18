import { defineConfig } from 'vitepress'
// .vitepress/config.mts
import { defineTeekConfig } from "vitepress-theme-teek/config";

// Teek 主题配置：defineTeekConfig 返回的对象必须合并进 defineConfig 才会生效。
// teekHome:false + vpHome:true 使用 VitePress 标准首页布局，避免出现空荡的博客风格右侧卡片。
const teekConfig = defineTeekConfig({
  teekHome: false,
  vpHome: true,
  vitePlugins: {
    // 关闭文章统计插件，不再扫描/统计文档
    docAnalysis: false,
    // 关闭自动生成侧边栏插件，侧边栏由下方 themeConfig.sidebar 手动维护
    sidebar: false,
  },
});

// https://vitepress.dev/reference/site-config
export default defineConfig({
  // 合并 Teek 注入的 vite / markdown / ignoreDeadLinks 等配置
  ...teekConfig,

  title: "LEMON IPW",
  description: "柠檬味 ipw.cn 替代品 · 文档（占位）",
  lang: "zh-CN",
  cleanUrls: true,

  themeConfig: {
    // 合并 Teek 的 themeConfig（如 teekHome 等开关）
    ...teekConfig.themeConfig,

    nav: [
      { text: 'Home', link: '/' },
      { text: '部署', link: '/guide/' },
      { text: 'GitHub', link: 'https://github.com/nomdn/ipw-cn', target: '_blank' },
    ],

    sidebar: [
      // 上级分组：部署（新增页面时在 items 里补一条即可）
      {
        text: '部署',
        items: [
          { text: '部署指南', link: '/guide/' },
          { text: '前端部署', link: '/guide/deploy-frontend' },
        ],
      },
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/nomdn/ipw-cn' },
    ],

    search: {
      provider: 'local',
    },
  },
})
