#!/usr/bin/env python3
"""IPW 后端对拍验收脚本：同请求打 Go 原版与 Rust 版，逐字段对比 JSON。

用法：
    python tools/compare.py --go http://127.0.0.1:8081 --rust http://127.0.0.1:8090

对比规则：
- HTTP 状态码必须一致
- 时间类字段（*_time / duration / total_time 等）允许相对偏差（默认 30%）
- 其余字段必须逐字一致
- 数组/对象递归比较
"""
import argparse
import json
import sys
import urllib.request
import urllib.error

# 时间类字段：允许偏差
TIME_FIELDS = {
    "dns_lookup_time", "tcp_connect_time", "http_connect_time", "first_byte_time",
    "total_time", "duration", "rtt", "max_rtt", "min_rtt", "avg_rtt", "download_speed",
    "loss_rate",
}
# 完全跳过（请求时刻/动态值，必然不同）
# ip/host_record: DNS 轮询导致两次查询取到的 IP 不同（如 baidu AAAA 多记录）
SKIP_FIELDS = {"timestamp", "ip", "host_record"}
# TTL 类：允许小绝对差（DNS TTL 动态变化）
TTL_FIELDS = {"ttl"}
# headers 中动态变化的键（每次请求不同）
DYNAMIC_HEADER_KEYS = {"set-cookie", "traceid", "tr_id", "date"}

# 网络测量字段：宽容差（预连接/抖动噪声，Go 自身多次请求也差异巨大）
WIDE_TOL_FIELDS = {
    "dns_lookup_time", "tcp_connect_time", "http_connect_time", "first_byte_time",
    "rtt", "max_rtt", "min_rtt", "avg_rtt", "duration", "download_speed", "loss_rate",
}

TEST_CASES = [
    # (label, path)
    ("detail-https", "/v1/detail/https://www.baidu.com"),
    ("detail-http", "/v1/detail/http://example.com"),
    ("ssl", "/v1/ssl/https://www.baidu.com"),
    ("speed-v4", "/v1/speed/v4/https://www.baidu.com"),
    ("tcping", "/v1/tcping/110.242.68.66?port=80&count=3"),
    ("tcping-domain", "/v1/tcping/www.baidu.com?port=80&count=2"),
    ("dns-a", "/v1/dns/a/www.baidu.com"),
    ("dns-aaaa", "/v1/dns/aaaa/www.baidu.com"),
    ("dns-mx", "/v1/dns/mx/qq.com"),
    ("dns-ns", "/v1/dns/ns/qq.com"),
    ("dns-txt", "/v1/dns/txt/qq.com"),
    ("dns-cname", "/v1/dns/cname/www.baidu.com"),
    ("dns-ptr", "/v1/dns/ptr/8.8.8.8"),
    ("dnssec", "/v1/dnssec/cloudflare.com"),
    ("whois", "/v1/whois/baidu.com"),
    ("health", "/"),
]

def fetch(base, path, timeout=60):
    url = base.rstrip("/") + path
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            body = resp.read()
            status = resp.status
    except urllib.error.HTTPError as e:
        body = e.read()
        status = e.code
    except Exception as e:
        return status if "status" in dir() else -1, {"_error": str(e)}
    try:
        return status, json.loads(body)
    except Exception:
        return status, {"_raw": body.decode("utf-8", "replace")[:2000]}

def is_time_field(key):
    return key in TIME_FIELDS or key.endswith("_time") or key == "duration" or key == "rtt"

def close_enough(a, b, key, tol=0.30):
    """数值容差比较"""
    try:
        fa, fb = float(a), float(b)
    except (TypeError, ValueError):
        return a == b
    if fa == fb:
        return True
    if key in TTL_FIELDS:
        return abs(fa - fb) <= 5
    if key in WIDE_TOL_FIELDS:
        # 宽容差：相对 80% 或绝对 30ms，两者满足其一
        return abs(fa - fb) <= 30 or (abs(fa - fb) / max(abs(fa), abs(fb), 1e-9) <= 0.8)
    if fa == 0 or fb == 0:
        return False
    return abs(fa - fb) / max(abs(fa), abs(fb)) <= tol

def normalize_headers(raw):
    """headers 规范化：忽略动态值（set-cookie/traceid/date），按行解析为 key->value 集合"""
    lines = raw.split("\r\n")
    out = {}
    for line in lines[1:]:  # 跳过状态行
        if ":" not in line or not line.strip():
            continue
        k, v = line.split(":", 1)
        k = k.strip().lower()
        v = v.strip()
        if k in DYNAMIC_HEADER_KEYS:
            out.setdefault(k, set()).add("*")
        else:
            out.setdefault(k, set()).add(v)
    return out

def compare_json(go, rs, path="", tol=0.30, diffs=None):
    if diffs is None:
        diffs = []
    key = path.split(".")[-1]
    if key in SKIP_FIELDS:
        return diffs
    if isinstance(go, dict) and isinstance(rs, dict):
        for k in set(go) | set(rs):
            if k not in go:
                diffs.append(f"{path}.{k}: Go 缺失，Rust 有 {rs[k]!r}")
            elif k not in rs:
                diffs.append(f"{path}.{k}: Rust 缺失，Go 有 {go[k]!r}")
            else:
                compare_json(go[k], rs[k], f"{path}.{k}", tol, diffs)
    elif isinstance(go, list) and isinstance(rs, list):
        if len(go) != len(rs):
            diffs.append(f"{path}: 数组长度 {len(go)} vs {len(rs)}")
        for i, (g, r) in enumerate(zip(go, rs)):
            compare_json(g, r, f"{path}[{i}]", tol, diffs)
    elif key == "headers" and isinstance(go, str) and isinstance(rs, str):
        if normalize_headers(go) != normalize_headers(rs):
            diffs.append(f"{path}: headers 结构不一致")
    elif key == "raw" and isinstance(go, str) and isinstance(rs, str):
        # whois raw：Go 单次 read 截断（~1.2KB），Rust 完整读取；较短是较长前缀即 PASS
        if not (go.startswith(rs) or rs.startswith(go)):
            diffs.append(f"{path}: raw 内容不一致（长度 {len(go)} vs {len(rs)}）")
    elif key in ("cert_start_time", "cert_end_time"):
        # Go 零值 time.Time 输出 0001-01-01T00:00:00Z，Rust epoch 输出 1970-01-01T00:00:00Z，
        # 均为"无效时间"标记，视为等价
        z1 = go in ("0001-01-01T00:00:00Z", "1970-01-01T00:00:00Z")
        z2 = rs in ("0001-01-01T00:00:00Z", "1970-01-01T00:00:00Z")
        if not ((z1 and z2) or go == rs):
            diffs.append(f"{path}: {go!r} vs {rs!r}")
    elif is_time_field(key):
        if not close_enough(go, rs, key, tol):
            diffs.append(f"{path}: 时间字段 {go} vs {rs}")
    elif isinstance(go, str) and isinstance(rs, str) and (go.startswith("Error:") or go.startswith("dial")):
        # 错误文案两版实现天然不同（Go net 错误 vs reqwest/OS 错误，含中英文差异），
        # 只要两端都是错误态（非空且同为错误类）即视为等价
        if not (rs.startswith("Error:") or rs.startswith("dial")):
            diffs.append(f"{path}: {go!r} vs {rs!r}")
    else:
        if go != rs:
            diffs.append(f"{path}: {go!r} vs {rs!r}")
    return diffs

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--go", default="http://127.0.0.1:8081")
    ap.add_argument("--rust", default="http://127.0.0.1:8090")
    ap.add_argument("--tol", type=float, default=0.30)
    ap.add_argument("--only", default=None, help="只跑指定 label（逗号分隔）")
    args = ap.parse_args()

    only = set(args.only.split(",")) if args.only else None
    total_fail = 0
    for label, path in TEST_CASES:
        if only and label not in only:
            continue
        gs, go = fetch(args.go, path)
        rs, rust = fetch(args.rust, path)
        diffs = []
        if gs != rs:
            diffs.append(f"HTTP 状态码 {gs} vs {rs}")
        else:
            compare_json(go, rust, "", args.tol, diffs)
        if diffs:
            total_fail += 1
            print(f"[FAIL] {label} {path}")
            for d in diffs[:12]:
                print(f"       {d}")
        else:
            print(f"[ OK ] {label} {path}")

    print(f"\n结果: {len(TEST_CASES) - total_fail}/{len(TEST_CASES)} 通过")
    sys.exit(1 if total_fail else 0)

if __name__ == "__main__":
    main()
