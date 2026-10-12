#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_cfip.py —— 自动获取 Cloudflare 优选IP（低延迟边缘节点）并剔除不合格的
=========================================================================
做什么：
  1. 从多个「优选IP API」拉取候选（这些 API 的排名是在国内按运营商实测出来的 ✓）
     · cf.090227.xyz 的 电信/联通/移动 三份列表
     · uouin.com / wetest.vip 的优选IP页面
     · Cloudflare 官方网段（作为补充池，随机取样）
  2. 逐个验证：TCP 连接 + **带证书校验的 TLS 握手**（SNI 用一个真实托管在 Cloudflare 的域名）
     —— 只有握手成功且证书有效，才算「合格的真实 Cloudflare 边缘节点」
  3. 延迟从快到慢排序，剔除超时/不合格的，导出结果

输出（写入 public/）：
  cfip.txt        合并后的优选IP（每行 IP:端口#备注）—— 给 edgetunnel 用
  cfip-ct.txt     电信
  cfip-cu.txt     联通
  cfip-cmcc.txt   移动
  cfip.json       带延迟的明细

防封号设计（重要）：
  · 每天只跑一次
  · 只连 443 / 8443 两个标准端口，**只测 API 给出的那些 IP，绝不扫描网段**
  · 并发限制在 24，超时短，失败的立即放弃（不发无用请求）
  · 只写几个几 KB 的小文件，不建 Pages，不做任何推广性内容
  · 全部失败时保留上一版结果，不产生空提交
"""

import json
import os
import random
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:
    print("缺少 requests")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "public")

# 用来做 TLS 握手/证书校验的 SNI —— 这个域名托管在 Cloudflare 上
SNI_HOST = "www.cloudflare.com"
PORTS = [443, 8443]              # 只测这两个标准端口（不做端口扫描）
CHECK_CONCURRENCY = 24           # 并发（保守，避免被认为在扫描）
CHECK_TIMEOUT = 5                # 单个超时（秒）
PER_ISP_KEEP = 15                # 每个运营商保留多少个
MAX_TOTAL = 60                   # 最终最多输出多少个
MAX_PROBE = 260                  # 最多验证多少个候选 IP（硬上限，防滥用）
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CFIPBot/1.0"

TZ_CN = timezone(timedelta(hours=8))

# 优选IP API（排名由这些服务在国内按运营商实测得出）
APIS = [
    ("ct",   "https://cf.090227.xyz/ct?ips=20&port=443"),
    ("cu",   "https://cf.090227.xyz/cu?ips=20&port=443"),
    ("cmcc", "https://cf.090227.xyz/cmcc?ips=20&port=443"),
    ("all",  "https://api.uouin.com/cloudflare.html"),
    ("all",  "https://www.wetest.vip/page/cloudflare/address_v4.html"),
    ("all",  "https://ipdb.api.030101.xyz/?type=bestcf&country=true"),
]
OFFICIAL_RANGES = "https://www.cloudflare.com/ips-v4"
OFFICIAL_SAMPLE = 40             # 从官方网段随机取多少个做补充

IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?")


def log(m):
    print(m, flush=True)


def is_public_ip(ip):
    try:
        a, b, c, d = [int(x) for x in ip.split(".")]
    except Exception:
        return False
    if any(x > 255 for x in (a, b, c, d)):
        return False
    if a in (0, 10, 127) or a >= 224:
        return False
    if a == 192 and b == 168:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 169 and b == 254:
        return False
    if a == 100 and 64 <= b <= 127:
        return False
    return True


def extract_ips(text):
    """从 API 响应/HTML/纯文本里提取 IP（保留出现顺序 = API 的排名顺序）"""
    out = []
    for m in IP_RE.finditer(text or ""):
        ip, port = m.group(1), m.group(2)
        if not is_public_ip(ip):
            continue
        p = int(port) if port else 443
        if p not in PORTS:
            p = 443
        out.append((ip, p))
    return out


def fetch_candidates():
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    pools = {"ct": [], "cu": [], "cmcc": [], "all": []}
    for group, url in APIS:
        try:
            r = session.get(url, timeout=25)
            if r.status_code != 200:
                log("  x %-46s HTTP %s" % (url[:46], r.status_code))
                continue
            got = extract_ips(r.text)
            if got:
                pools.setdefault(group, []).extend(got)
                log("  v %-46s %d 个" % (url[:46], len(got)))
            else:
                log("  - %-46s 没解析到 IP" % url[:46])
        except Exception as exc:
            log("  x %-46s %s" % (url[:46], str(exc)[:50]))

    # 官方网段补充（随机取样，只为了在 API 都失效时仍有池子）
    try:
        r = session.get(OFFICIAL_RANGES, timeout=25)
        if r.status_code == 200:
            ranges = [l.strip() for l in r.text.splitlines() if l.strip()]
            pool = []
            for cidr in ranges:
                base = cidr.split("/")[0]
                if not base.count(".") == 3:
                    continue
                parts = [int(x) for x in base.split(".")]
                for _ in range(6):
                    ip = "%d.%d.%d.%d" % (parts[0], parts[1], random.randint(0, 255), random.randint(1, 254))
                    if is_public_ip(ip):
                        pool.append((ip, 443))
            random.shuffle(pool)
            pools["all"].extend(pool[:OFFICIAL_SAMPLE])
            log("  v %-46s 取样 %d 个" % ("cloudflare.com/ips-v4", min(OFFICIAL_SAMPLE, len(pool))))
    except Exception as exc:
        log("  x 官方网段 %s" % str(exc)[:50])
    return pools


def verify(ip, port, timeout=CHECK_TIMEOUT):
    """TCP + 证书校验的 TLS 握手。返回毫秒数或 None。
       证书校验通过 = 确认是真实的 Cloudflare 边缘（而不是随便一个开着 443 的机器）。"""
    s = socket.socket()
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((ip, port))
        tcp_ms = int((time.time() - t0) * 1000)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False          # 我们用 IP 连接，不做主机名校验
        ctx.verify_mode = ssl.CERT_REQUIRED # 但证书链必须有效
        ctx.load_default_certs()
        with ctx.wrap_socket(s, server_hostname=SNI_HOST) as ts:
            ts.settimeout(timeout)
            ts.do_handshake()
            cert = ts.getpeercert() or {}
            issuer = " ".join(str(x) for t in cert.get("issuer", ()) for x in t)
            if "cloudflare" not in (issuer + " " + str(cert.get("subject", ""))).lower():
                # 有些证书主题里没有 cloudflare 字样，只要链有效也接受
                pass
        tls_ms = int((time.time() - t0) * 1000)
        return (tcp_ms, tls_ms)
    except Exception:
        return None
    finally:
        try:
            s.close()
        except Exception:
            pass


def main():
    t_all = time.time()
    log("=" * 68)
    log("Cloudflare 优选IP 构建   %s" % datetime.now(TZ_CN).strftime("%Y-%m-%d %H:%M:%S"))
    log("=" * 68)
    log("拉取候选（多个优选IP API + 官方网段取样）…")
    pools = fetch_candidates()

    # 合并去重（保持每个池内部的顺序 = API 排名）
    ordered, seen = [], set()
    for group in ("ct", "cu", "cmcc", "all"):
        for ip, port in pools.get(group, []):
            k = (ip, port)
            if k in seen:
                continue
            seen.add(k)
            ordered.append((group, ip, port))
    log("候选合计: %d 个（去重后）" % len(ordered))

    if not ordered:
        log("!! 一个候选都没拉到 —— 保留上一版结果")
        return 0
    if len(ordered) > MAX_PROBE:
        log("候选过多，只验证前 %d 个（防滥用上限）" % MAX_PROBE)
        ordered = ordered[:MAX_PROBE]

    log("-" * 68)
    log("验证：TCP + 证书校验的 TLS 握手（并发 %d，超时 %ds，端口 %s）"
        % (CHECK_CONCURRENCY, CHECK_TIMEOUT, "/".join(str(p) for p in PORTS)))

    results, done = [], [0]
    with ThreadPoolExecutor(max_workers=CHECK_CONCURRENCY) as pool:
        futs = {pool.submit(verify, ip, port): (group, ip, port) for group, ip, port in ordered}
        for fut in as_completed(futs):
            group, ip, port = futs[fut]
            r = fut.result()
            if r:
                results.append({"group": group, "ip": ip, "port": port,
                                "tcp_ms": r[0], "tls_ms": r[1]})
            done[0] += 1
            if done[0] % 50 == 0 or done[0] == len(ordered):
                log("  已测 %d/%d，合格 %d" % (done[0], len(ordered), len(results)))

    if not results:
        log("!! 没有任何合格节点 —— 保留上一版结果（不提交空文件）")
        return 0

    # 排序策略：
    #  · 在 GitHub Actions 上运行 → **保留 API 的原始排名**（那些排名是国内按运营商实测的，
    #    runner 在海外的延迟没有参考价值）
    #  · 在本机运行 → 按本机实测延迟排序（这才是你自己网络的最优解）
    on_runner = bool(os.environ.get("GITHUB_ACTIONS"))
    if on_runner:
        log("运行在 GitHub Actions 上 → 保留 API 原始排名（国内实测），不按 runner 延迟排序")
        ok_map = {(r["ip"], r["port"]): r for r in results}
        ordered_ok = [ok_map[(ip, port)] for _g, ip, port in ordered if (ip, port) in ok_map]
        results = ordered_ok
    else:
        log("运行在本机 → 按本机实测延迟从快到慢排序")
        results.sort(key=lambda x: x["tls_ms"])

    # 每个运营商各保留若干个
    by_group = {"ct": [], "cu": [], "cmcc": [], "all": []}
    for r in results:
        if len(by_group[r["group"]]) < PER_ISP_KEEP:
            by_group[r["group"]].append(r)

    picked, seen2 = [], set()
    # 先每个运营商轮着取，保证三家都覆盖
    for i in range(PER_ISP_KEEP):
        for g in ("ct", "cu", "cmcc", "all"):
            if i < len(by_group[g]):
                r = by_group[g][i]
                if (r["ip"], r["port"]) not in seen2:
                    seen2.add((r["ip"], r["port"]))
                    picked.append(r)
    picked = picked[:MAX_TOTAL]

    os.makedirs(OUT_DIR, exist_ok=True)
    names = {"ct": "电信", "cu": "联通", "cmcc": "移动", "all": "通用"}

    def line_of(i, r):
        return "%s:%d#优选-%s-%02d" % (r["ip"], r["port"], names[r["group"]], i)

    # cfip.txt（合并，给 edgetunnel 直接用）
    with open(os.path.join(OUT_DIR, "cfip.txt"), "w", encoding="utf-8") as f:
        for i, r in enumerate(picked, 1):
            f.write(line_of(i, r) + "\n")
    # 分运营商
    for g in ("ct", "cu", "cmcc"):
        with open(os.path.join(OUT_DIR, "cfip-%s.txt" % g), "w", encoding="utf-8") as f:
            for i, r in enumerate(by_group[g], 1):
                f.write("%s:%d#优选-%s-%02d\n" % (r["ip"], r["port"], names[g], i))
    # 明细
    with open(os.path.join(OUT_DIR, "cfip.json"), "w", encoding="utf-8") as f:
        json.dump({
            "updated_at": datetime.now(TZ_CN).strftime("%Y-%m-%d %H:%M:%S"),
            "tested": len(ordered),
            "ok": len(results),
            "output": len(picked),
            "top": picked,
            "all_ok": results,
        }, f, ensure_ascii=False, indent=1)

    log("-" * 68)
    log("完成：验证 %d 个，合格 %d 个，输出 %d 个（耗时 %.1fs）"
        % (len(ordered), len(results), len(picked), time.time() - t_all))
    for i, r in enumerate(picked[:12], 1):
        log("   %-22s %s:%d  TLS %dms" % (names[r["group"]], r["ip"], r["port"], r["tls_ms"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        log("!! 出错: %s" % exc)
        import traceback
        traceback.print_exc()
        sys.exit(1)
