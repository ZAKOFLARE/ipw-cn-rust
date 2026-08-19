#!/usr/bin/env bash
# IPW Linux 交叉编译脚本（Windows Git Bash / Linux / macOS 通用）
#
# 原理：cargo-zigbuild —— zig 作为交叉链接器 + C 编译器，
#   自动处理 ring / aws-lc-sys / zstd-sys 等 C 依赖的交叉编译，
#   Windows 开发机上无需安装 Linux 交叉 gcc。
#
# 产物：dist/ipw-{backend,middleware}-linux-{amd64,arm64,armv7}（静态链接 musl）
#
# 用法：
#   bash tools/cross-build.sh              # 三个架构全量构建
#   bash tools/cross-build.sh --only amd64  # 只构建 amd64
#   bash tools/cross-build.sh --only windows # 只构建 Windows 版
#   ZIG_VERSION=0.14.1 bash tools/cross-build.sh  # 指定 zig 版本
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

# cargo / rustup / cargo-zigbuild 路径
export PATH="$HOME/.cargo/bin:$PATH"

ZIG_VERSION="${ZIG_VERSION:-0.13.0}"
DIST_DIR="${DIST_DIR:-$ROOT/dist}"
ZIG_HOME="${ZIG_HOME:-$ROOT/tools/.zig}"
mkdir -p "$ZIG_HOME" "$ROOT/tools"
export PATH="$ZIG_HOME:$PATH"

# 解析 --only 参数
ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --only) shift; ONLY="${1:-}" ;;
    --only=*) ONLY="${1#--only=}" ;;
  esac
  shift
done

# 平台检测
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) PLATFORM="windows-x86_64" ;;
  Linux)
    case "$(uname -m)" in
      x86_64) PLATFORM="linux-x86_64" ;;
      aarch64) PLATFORM="linux-aarch64" ;;
      *) echo "unsupported linux arch: $(uname -m)"; exit 1 ;;
    esac
    ;;
  Darwin)
    case "$(uname -m)" in
      arm64) PLATFORM="macos-aarch64" ;;
      x86_64) PLATFORM="macos-x86_64" ;;
    esac
    ;;
  *) echo "unsupported platform: $(uname -s)"; exit 1 ;;
esac

# target 列表(linux 走 musl 静态;windows 走 gnu 交叉)
TARGETS=(
  "x86_64-unknown-linux-musl|amd64"
  "aarch64-unknown-linux-musl|arm64"
  "armv7-unknown-linux-musleabihf|armv7"
  "x86_64-pc-windows-gnu|windows"
)

echo "==> platform: $PLATFORM | zig: $ZIG_VERSION | output: $DIST_DIR"

# 1. rustup 安装交叉 target
for entry in "${TARGETS[@]}"; do
  target="${entry%%|*}"
  arch="${entry##*|}"
  [ -n "$ONLY" ] && [ "$ONLY" != "$arch" ] && continue
  echo "==> rustup target add $target"
  rustup target add "$target"
done

# 2. zig（静态链接器）
if ! command -v zig > /dev/null 2>&1; then
  if [ -x "$ZIG_HOME/zig" ]; then
    echo "==> using local zig: $ZIG_HOME/zig"
  else
    echo "==> downloading zig $ZIG_VERSION ($PLATFORM)..."
    case "$PLATFORM" in
      windows-x86_64)
        # 注意：-o 用相对路径（原生 curl.exe 不识别 Git Bash 的 /c/ 绝对路径）
        (cd "$ROOT/tools" && curl -fL --ssl-no-revoke -o zig.zip           "https://ziglang.org/download/$ZIG_VERSION/zig-windows-x86_64-$ZIG_VERSION.zip")
        # Windows 自带 bsdtar 解 zip 秒级；--strip-components 直接落到 ZIG_HOME，避免整目录删除
        # 注意：bsdtar 是原生 Windows 程序，不识别 Git Bash 的 /c/ 路径，必须用相对路径
        (cd "$ZIG_HOME" && /c/Windows/System32/tar.exe -xf "../zig.zip" --strip-components 1)
        # zip 留作缓存（下次跳过下载）；删除失败不影响流程
        rm -f "$ROOT/tools/zig.zip" 2>/dev/null || true
        ;;
      linux-x86_64|linux-aarch64|macos-aarch64|macos-x86_64)
        (cd "$ROOT/tools" && curl -fL --ssl-no-revoke -o zig.tar.xz           "https://ziglang.org/download/$ZIG_VERSION/zig-$PLATFORM-$ZIG_VERSION.tar.xz")
        tar -xf "$ROOT/tools/zig.tar.xz" -C "$ZIG_HOME" --strip-components 1
        rm -f "$ROOT/tools/zig.tar.xz" 2>/dev/null || true
        ;;
    esac
  fi
  echo "==> zig version: $($ZIG_HOME/zig version 2>/dev/null || zig version)"
fi

# 3. cargo-zigbuild
if ! command -v cargo-zigbuild > /dev/null 2>&1; then
  echo "==> installing cargo-zigbuild (cargo install, first run ~2-5 min)..."
  cargo install cargo-zigbuild
fi

# 4. 构建 + 收集产物
mkdir -p "$DIST_DIR"
for entry in "${TARGETS[@]}"; do
  target="${entry%%|*}"
  arch="${entry##*|}"
  [ -n "$ONLY" ] && [ "$ONLY" != "$arch" ] && continue

  echo "==> building $target ..."
  cargo zigbuild --release --target "$target" \
    --bin ipw-backend --bin ipw-middleware

  if [ "$arch" = "windows" ]; then
    cp "target/$target/release/ipw-backend.exe"   "$DIST_DIR/ipw-backend-windows-amd64.exe"
    cp "target/$target/release/ipw-middleware.exe" "$DIST_DIR/ipw-middleware-windows-amd64.exe"
    echo "==> done: $DIST_DIR/ipw-{backend,middleware}-windows-amd64.exe"
  else
    cp "target/$target/release/ipw-backend"   "$DIST_DIR/ipw-backend-linux-$arch"
    cp "target/$target/release/ipw-middleware" "$DIST_DIR/ipw-middleware-linux-$arch"
    echo "==> done: $DIST_DIR/ipw-{backend,middleware}-linux-$arch"
  fi
done

echo
echo "==> all done. artifacts in $DIST_DIR:"
ls -lh "$DIST_DIR"
echo
echo "deploy on server:"
echo "  ./ipw-backend-linux-amd64   # 默认读取同目录 setting.json，端口 8080"
echo "  或 PORT=30000 ./ipw-backend-linux-amd64"
