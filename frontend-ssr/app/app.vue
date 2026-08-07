<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref } from 'vue';
import { useDark, useToggle } from '@vueuse/core';
import { Moon, Sunny, Expand } from '@element-plus/icons-vue';
import { config } from '../config/index';


const isNarrow = ref(false);
let mediaQueryList: MediaQueryList | null = null;
const drawer = ref(false);

const isDark = useDark();
const toggleDark = useToggle(isDark);

function Announcement() {
  ElMessage({
    showClose: true,
    message: '您好,这里是LEMONIPW开发团队,我们很重视您对本项目的意见,诚邀您加入官方交流群进行讨论,欢迎您的加入!QQ:<a href="https://qm.qq.com/q/E1CGjkqgG6" >点我</a>',
    duration: 3000,
    dangerouslyUseHTMLString: true,
  });
}
function cleanChineseCharacters(input: string): string {
  // 使用正则表达式匹配中文字符
  const chineseRegex = /[\u4e00-\u9fa5]/g;
  // 将中文字符替换为空字符串
  return input.replace(chineseRegex, '');
}
onMounted(() => {
  mediaQueryList = window.matchMedia('(max-width: 768px)');
  isNarrow.value = mediaQueryList.matches;

  const handler = (e: MediaQueryListEvent) => {
    isNarrow.value = e.matches;
  };

  mediaQueryList.addEventListener('change', handler);

  onBeforeUnmount(() => {
    mediaQueryList?.removeEventListener('change', handler);
  });
});

useHead({
  // 在 HTML 解析前同步执行，防止明暗切换和页面闪烁
  script: [
    {
      defer: true,
      src: config.umamiScriptUrl,
      'data-website-id': config.umamiWebsiteId,
    },
  ],
  meta: config.noindex
    ? [
        { name: 'robots', content: 'noindex, nofollow' },
        { name: 'googlebot', content: 'noindex, nofollow' },
        { name: 'bingbot', content: 'noindex, nofollow' },
      ]
    : [],
});
</script>

<template>
  
  <el-drawer v-if="isNarrow" v-model="drawer" direction="ltr" style="height: 100%;" size="50%">
      <router-link to="/ipv6webcheck" style="font-size: 1em;">
        <p style="display: inline-block; margin-left: 10px">IPv6 网站检测</p>
      </router-link>
      <router-link to="/location" style="font-size: 1em;">
        <p style="display: inline-block; margin-left: 10px">IPv6/IPv4 地址查询</p>
      </router-link>
      <router-link to="/ipv6tcping" style="font-size: 1em;">
        <p style="display: inline-block; margin-left: 10px">IPv6 TCPing</p>
      </router-link>
      <router-link to="/dns"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv6 DNS解析</p></router-link>
      <router-link to="/ssl" style="font-size: 1em;">
        <p style="display: inline-block; margin-left: 10px">IPv6 SSL检查</p>
      </router-link>
      <a href="/ipv6speedtest"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv6 网站测速</p></a>
      <a href="/speedtest"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv4 网站测速</p></a>
      <a href="/tcping"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv4 TCPing</p></a>
      <a href="/screenshot"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">网站截图</p></a>
      <a href="/whois"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">RDAP Whois查询</p></a>
  </el-drawer>
  <el-menu
      mode="horizontal"
      :ellipsis="false"
      
    >
    <el-menu-item index="0">
      <el-icon v-if="isNarrow" @click="drawer = !drawer"><Expand /></el-icon>
      <router-link to="/">
        <el-image src="/favicon.svg" style="margin-top: 20px;" /> 
        <h2 style="display: inline-block; margin-left: 10px" v-if="!isNarrow">柠檬味ipw.cn</h2>
      </router-link>
    </el-menu-item>
    
    <el-menu-item index="1" v-if="!isNarrow">
      <router-link to="/ipv6webcheck" style="font-size: 1em;">
        <p style="display: inline-block; margin-left: 10px">IPv6 网站检测</p>
      </router-link>
    </el-menu-item>
    <el-menu-item index="2" v-if="!isNarrow">
      <router-link to="/location">
        <p style="display: inline-block; margin-left: 10px">IPv6/IPv4 地址查询</p>
      </router-link>
    </el-menu-item>
    <el-menu-item index="3" v-if="!isNarrow">
      <router-link to="/ipv6tcping"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv6 TCPing测试</p></router-link>
    </el-menu-item>

    <el-divider style="margin-top: 20px;height: 1.2em;" direction="vertical" v-if="!isNarrow"/>

    <el-menu-item index="4" v-if="!isNarrow">
      <router-link to="/dns"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv6 DNS解析</p></router-link>
    </el-menu-item>
    <el-menu-item index="5" v-if="!isNarrow">
      <router-link to="/ssl">
        <p style="display: inline-block; margin-left: 10px">IPv6 SSL检查</p>
      </router-link>
    </el-menu-item>
    <el-menu-item index="6" v-if="!isNarrow">
      <router-link to="/ipv6speedtest"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv6 网站测速</p></router-link>
    </el-menu-item>
    <el-divider style="margin-top: 20px;height: 1.2em;" direction="vertical" v-if="!isNarrow"/>
    <el-sub-menu index="7" v-if="!isNarrow">
      <template #title>IPv4工具箱</template>
      <el-menu-item index="7-0">
        <router-link to="/speedtest"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv4 网站测速</p></router-link>
      </el-menu-item>
      <el-menu-item index="7-1">
        <router-link to="/tcping"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">IPv4 TCPing测试</p></router-link>
      </el-menu-item>
    </el-sub-menu>
    <el-sub-menu index="8" v-if="!isNarrow">
      <template #title>其他工具</template>
      <el-menu-item index="8-0">
        <router-link to="/screenshot"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">网站截图</p></router-link>
      </el-menu-item>
      <el-menu-item index="8-1">
        <router-link to="/whois"  style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">RDAP Whois查询</p></router-link>
      </el-menu-item>
    </el-sub-menu>
    <el-menu-item index="9" v-if="!isNarrow">
      <router-link to="/doc" style="font-size: 1em;"><p style="display: inline-block; margin-left: 10px">文档</p></router-link>
    </el-menu-item>
    <el-menu-item index="10">
      <ClientOnly>
      <el-icon @click="toggleDark()" v-if="isDark" style="cursor: pointer;"><Moon style="height: 20px; width: 20px;"/></el-icon>
      <el-icon @click="toggleDark()" v-else style="cursor: pointer;"><Sunny style="height: 20px; width: 20px;"/></el-icon>
      </ClientOnly>
    </el-menu-item>


  </el-menu>
  
  <NuxtLoadingIndicator />
  <main id="main-content" role="main">
    <NuxtPage />
  </main>

  <footer>
    <div class="one-line">
      Copyright © nomdn & IP 查询 2026  | <img src="/ipv6-s1.svg" alt="IPv6 相关标识"/> | <img src="/ssl-s1.svg" alt="SSL 相关标识"/> | All right reserved
    </div>
    <div class="one-line">
      <a v-if="config.ICP" href="https://beian.miit.gov.cn/" target="_blank" rel="noreferrer" >{{ config.ICP }}</a>
      <span v-if="config.ICP">&nbsp;|&nbsp;</span>
      <el-image v-if="config.GongAn" style="height: 1em; width: 1em;" src="/备案图标.png" />
      <a :href="'https://beian.mps.gov.cn/#/query/webSearch?code=' + cleanChineseCharacters(config.GongAn)" target="_blank" rel="noreferrer" >{{ config.GongAn }}</a>
      <span v-if="config.GongAn">&nbsp;|&nbsp;</span>
      <a href="https://www.china-ipv6.cn/" target="_blank" rel="noreferrer" >国家IPv6发展监测平台</a>
      &nbsp;|&nbsp;请遵守中国法律法规&nbsp;|&nbsp;
      <a href="https://github.com/nomdn/ipw-cn" target="_blank" rel="noreferrer" >Github</a>&nbsp;|&nbsp;
      <a href="https://qm.qq.com/q/E1CGjkqgG6" target="_blank" rel="noreferrer" >QQ用户交流群</a>
   </div>
   <div class="one-line">
      致力于普及IPv6，推进IPv6规模部署和应用，以全面推进IPv6技术创新与融合应用为主线，以提升应用广度深度为主攻方向
  </div>
  </footer>

</template>
<style scoped>
@import "~/style.css";
.el-menu--horizontal > .el-menu-item:nth-child(1) {
  margin-right: auto;
}
:deep(.shiki span) {
  font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'Consolas', 'Monaco', 'Courier New', monospace !important;
  word-wrap:break-word;
}
:deep(.shiki){
  padding: 20px;
  border-radius: 10px;
}

:deep(.el-menu-item a) {
  font-size: 1em;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
:deep(.el-menu-item a p) {
  font-size: 1em;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
:deep(.el-menu-item a img) {
  width: 50px;
  margin-bottom: 20px;
  
}
</style>
<style>
:root {
  --el-color-primary: #3EAF7C;
}
html.dark {
  --el-color-primary: #3EAF7C;
}

/* Drawer 内部链接占满一行 */
.el-drawer__body {
  overflow-x: hidden;
}
.el-drawer__body a {
  display: block !important;
  width: 100% !important;
  box-sizing: border-box;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.el-drawer__body a p {
  display: block !important;
  width: 100% !important;
  box-sizing: border-box;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

/* 防止窄屏设备在 Vue 水合前出现宽屏布局闪烁 */
html.is-narrow .el-drawer__container {
  display: none !important;
}
html.is-narrow .el-menu--horizontal > .el-divider {
  display: none !important;
}
html.is-narrow .el-menu--horizontal > .el-menu-item[index="1"],
html.is-narrow .el-menu--horizontal > .el-menu-item[index="2"],
html.is-narrow .el-menu--horizontal > .el-menu-item[index="3"],
html.is-narrow .el-menu--horizontal > .el-menu-item[index="4"],
html.is-narrow .el-menu--horizontal > .el-menu-item[index="5"],
html.is-narrow .el-menu--horizontal > .el-menu-item[index="6"],
html.is-narrow .el-menu--horizontal > .el-sub-menu[index="7"]
html.is-narrow .el-menu--horizontal > .el-sub-menu[index="8"]
html.is-narrow .el-menu--horizontal > .el-sub-menu[index="9"]
html.is-narrow .el-menu--horizontal > .el-sub-menu[index="10"] {
  display: none !important;
}
.el-menu--horizontal {
  --el-menu-hover-bg-color: transparent !important;
  --el-menu-active-color: var(--el-text-color-primary) !important;
  --el-menu-bg-color: transparent !important;
}

.el-menu--horizontal > .el-menu-item:nth-child(1) {
  margin-right: auto;
}

/* 去除选中强调和下划线 */
.el-menu--horizontal > .el-menu-item.is-active {
  color: var(--el-text-color-primary) !important;
  background-color: transparent !important;
}

.el-menu--horizontal > .el-menu-item:hover {
  color: var(--el-text-color-primary) !important;
  background-color: transparent !important;
}

/* 去除所有可能的边框和下划线 */
.el-menu--horizontal::after {
  display: none !important;
}

.el-menu--horizontal > .el-menu-item {
  border-bottom: none !important;
  transition: none !important;
}

.el-menu--horizontal > .el-menu-item.is-active::after {
  display: none !important;
}
</style>