#!/bin/bash
# IPW 对拍：同时启动 Go 原版与 Rust 版后端并运行对比
# 用法: bash tools/run-compare.sh

set -e
cd "$(dirname "$0")/.."
export PATH="$HOME/.cargo/bin:$PATH"

GO_DIR="../ipw-cn-main"
GO_PORT=8081
RUST_PORT=8090

echo "==> [1/4] 构建 Rust release"
cargo build --release -p ipw-backend

echo "==> [2/4] 启动 Go 原版 (端口 $GO_PORT, IPDB=false)"
cd "$GO_DIR"
export IPDB=false
export PORTS=$GO_PORT
export BLOCK_PRIVATE_IPS=true
export DNS_SERVER=""
go run main.go > /tmp/go-backend.log 2>&1 &
GO_PID=$!
cd - > /dev/null

echo "==> [3/4] 启动 Rust 版 (端口 $RUST_PORT)"
cd "$(dirname "$0")/.."
export PORT=$RUST_PORT
export RUST_LOG=info
./target/release/ipw-backend.exe > /tmp/rust-backend.log 2>&1 &
RUST_PID=$!

# 等待就绪
for i in $(seq 1 60); do
    if curl -sf "http://127.0.0.1:$GO_PORT/" > /dev/null 2>&1; then break; fi
    sleep 1
done
for i in $(seq 1 30); do
    if curl -sf "http://127.0.0.1:$RUST_PORT/" > /dev/null 2>&1; then break; fi
    sleep 1
done

echo "==> [4/4] 运行对拍"
python tools/compare.py --go "http://127.0.0.1:$GO_PORT" --rust "http://127.0.0.1:$RUST_PORT" "$@"
RC=$?

echo "==> 清理进程"
kill $GO_PID $RUST_PID 2>/dev/null || true
exit $RC
