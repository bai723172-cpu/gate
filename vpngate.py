#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线 (精简版)
=====================================
流程:
  1. 获取 VPN Gate 原始节点
  2. 只保留带 TCP 入口的 SSTP 节点
  3. 去重
  4. 并发调用检测 Worker
  5. 获取并合并优选域名与优选 API (Cloudflare 入口)
  6. 生成 public/data.json + public/index.html + public/nodes.txt
"""

import base64
import csv
import io
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import quote, urlparse

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

VPNGATE_API = os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/")
VPNGATE_MIRROR = os.environ.get(
    "VPNGATE_MIRROR",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
)
WORKER_CHECK_URL = os.environ.get("CHECK_WORKER", "https://你的域名/check?sstp=vpn:vpn@")
# [反风控] 并发从 32 降到 8：降低 Cloudflare Worker 瞬时压力，避免被 WAF 判定为攻击
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "8")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "90"))
# [反风控] 单次最多检测 400 个节点（0=不限制）。跑太多请求是触发风控的第一大原因
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "400"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "60"))
PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")

DATA_CENTER_ORG_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASWEB",
]
RESIDENTIAL_ORG_KEYWORDS = [
    "NTT EAST", "NTT WEST", "NTT COMMUNICATIONS", "NTT BROADBAND", "KDDI", "DOCOMO",
    "SOFTBANK", "AU COMMUNICATIONS", "J:COM", "JCOM", "OCN", "BIGLOBE",
    "IIJ", "SEIKO", "CLEVER-NET", "AT&T", "COMCAST", "XFINITY", "VERIZON",
    "TELUS", "ROGERS", "BELL CANADA", "VODAFONE", "ORANGE", "DEUTSCHE TELEKOM",
    "BREEZE", "TIM S.P.A", "LIBERO", "FASTWEB", "FREE FRANCE", "BT OPEN",
]

COUNTRY_ZH = {
    "JP": "日本", "KR": "韩国", "US": "美国", "CA": "加拿大", "RU": "俄罗斯",
    "RO": "罗马尼亚", "TH": "泰国", "VN": "越南", "DE": "德国", "FR": "法国",
    "GB": "英国", "UK": "英国", "SG": "新加坡", "TW": "台湾", "HK": "香港",
    "CN": "中国", "AU": "澳大利亚", "NL": "荷兰", "SE": "瑞典", "CH": "瑞士",
    "IT": "意大利", "ES": "西班牙", "PL": "波兰", "IN": "印度", "BR": "巴西",
    "MX": "墨西哥", "ID": "印度尼西亚", "MY": "马来西亚", "PH": "菲律宾",
    "TR": "土耳其", "UA": "乌克兰", "CZ": "捷克", "GR": "希腊", "PT": "葡萄牙",
    "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IE": "爱尔兰", "BE": "比利时",
    "AT": "奥地利", "HU": "匈牙利", "AR": "阿根廷", "CL": "智利", "CO": "哥伦比亚",
    "NZ": "新西兰", "ZA": "南非", "IL": "以色列", "AE": "阿联酋", "SA": "沙特",
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "GD": "格林纳达",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "LT": "立陶宛", "SK": "斯洛伐克",
    "SI": "斯洛文尼亚", "BG": "保加利亚", "RS": "塞尔维亚", "GE": "格鲁吉亚",
    "MD": "摩尔多瓦", "AM": "亚美尼亚", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "MN": "蒙古", "NP": "尼泊尔", "LK": "斯里兰卡", "MM": "缅甸",
}

# 静态优选域名池
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "saas.sin.fan:443,cdn.204910.best:443,www.mfyx.cn:443,p.etime.vip:443,cdn.ctn32.us.kg:443,cf.877774.xyz:443,spring.io:443,"
        "cf.nyanya.moe:443,www.sloomb.com:443,op.chinwa.eu.cc:443,www.leics.police.uk:443,securecircle.com:443,www.shopify.com:443,"
        "www.carousell.sg:443,www.dbs.com.sg:443,openai.com:443,linear.app:443,www.bilibili.com:443,uspto.gov:443,www.vmware.com:443",
    ).split(",")
    if h.strip()
]

# 优选 API 地址配置 (支持逗号分隔多个；默认三网分别取优: 电信 / 联通 / 移动)
OPTIMAL_API = os.environ.get(
    "OPTIMAL_API",
    "https://cf.090227.xyz/ct?ips=6&port=443,"
    "https://cf.090227.xyz/cu?port=443,"
    "https://cf.090227.xyz/cmcc?ips=8&port=443",
)

NODES_URL = os.environ.get("NODES_URL", "https://bai723172-cpu.github.io/gate/nodes.txt")

# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
_section = None

def log(section, msg=""):
    global _section
    if section != _section:
        print(f"========== {section} ==========")
        _section = section
    if msg:
        print(msg, flush=True)

def die(msg):
    log("FATAL", f"[失败] {msg}")
    sys.exit(1)

# ---------------------------------------------------------------------------
# [新增] 状态持久化 / 礼貌抓取 / 速率限制 / 多源优选 API
#  设计目标: 在拿到同样结果的前提下，把对外请求量压到最低 ——
#  这是避免被 Cloudflare、GitHub、VPN Gate 风控的唯一可靠办法（没有任何
#  "绕过检测" 的技巧，最好的保护就是用量远低于限额且行为像正常用户）。
# ---------------------------------------------------------------------------
import hashlib
import random
import socket
import threading

STATE_DIR = os.environ.get("STATE_DIR", os.path.join(REPO_DIR, "state"))
CHECK_CACHE_PATH = os.path.join(STATE_DIR, "check_cache.json")
KEEP_PATH = os.path.join(STATE_DIR, "residential_keep.json")
HTTP_CACHE_PATH = os.path.join(STATE_DIR, "http_cache.json")

USER_AGENT = os.environ.get("USER_AGENT", "gate-checker/2.0 (polite; +https://github.com/)")
REQUEST_MIN_INTERVAL = float(os.environ.get("REQUEST_MIN_INTERVAL", "1.2"))   # 同域名两次请求最小间隔(秒)
REQUEST_JITTER = float(os.environ.get("REQUEST_JITTER", "0.8"))               # 随机抖动上限(秒)
MAX_RETRIES = max(0, int(os.environ.get("MAX_RETRIES", "3")))                 # 失败重试次数
BACKOFF_BASE = float(os.environ.get("BACKOFF_BASE", "2.0"))                   # 指数退避基数
CHECK_BATCH_DELAY = float(os.environ.get("CHECK_BATCH_DELAY", "1.5"))         # 检测批次间隔(秒)
CHECK_CACHE_TTL = int(os.environ.get("CHECK_CACHE_TTL", str(6 * 3600)))       # 检测结果缓存(秒)
RESIDENTIAL_KEEP_DAYS = int(os.environ.get("RESIDENTIAL_KEEP_DAYS", "7"))     # 住宅好节点留存天数
# [默认开启] 只输出住宅节点；想同时输出机房节点就设 KEEP_RESIDENTIAL_ONLY=0
KEEP_RESIDENTIAL_ONLY = os.environ.get("KEEP_RESIDENTIAL_ONLY", "1").strip().lower() in ("1", "true", "yes", "on")
VALIDATE_ENDPOINTS = os.environ.get("VALIDATE_ENDPOINTS", "1").strip().lower() in ("1", "true", "yes", "on")
MAX_EDGE_ENDPOINTS = int(os.environ.get("MAX_EDGE_ENDPOINTS", "30"))          # 最终保留多少个优选入口
ENDPOINT_TIMEOUT = float(os.environ.get("ENDPOINT_TIMEOUT", "3"))             # 入口 TCP 验证超时
HTTP_CACHE_MAX_BODY = int(os.environ.get("HTTP_CACHE_MAX_BODY", "131072"))    # 只缓存 128KB 以内的响应正文
GITHUB_TOKEN = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()

# [新增] 公开优选 API 兜底源（全部实测可用 2026-10-12；只读公开接口，不做 IP 段扫描）
OPTIMAL_API_FALLBACKS = [
    "https://cf.090227.xyz/ct?ips=6&port=443",              # 电信 6 条
    "https://cf.090227.xyz/cu?port=443",                    # 联通
    "https://cf.090227.xyz/cmcc?ips=8&port=443",            # 移动 8 条
    "https://api.uouin.com/cloudflare.html",                # 公开榜单（实测一次 40 个 IP）
    "https://www.wetest.vip/page/cloudflare/address_v4.html",  # 公开榜单（实测 15 个 IP）
]

# [新增] VPN Gate 静态数据源（2026-10-12 全部实测能拿到 96~100 行节点数据）
VPNGATE_STATIC_SOURCES = [
    # 官方 API
    "http://www.vpngate.net/api/iphone/",
    "https://www.vpngate.net/api/iphone/",
    # GitHub 原始
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
    # jsDelivr 四个 CDN 节点（互为备份）
    "https://cdn.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json",
    "https://gcore.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json",
    "https://fastly.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json",
    "https://testingcf.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json",
    # GitHub 加速镜像
    "https://gh-proxy.com/https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
    "https://ghproxy.net/https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
    "https://ghfast.top/https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
    "https://gh.llkk.cc/https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
    "https://raw.githack.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
]

MAX_VPNGATE_SOURCES = int(os.environ.get("MAX_VPNGATE_SOURCES", "4"))   # 凑够几个可用源就停，避免多余请求
SOURCES_PATH = os.path.join(STATE_DIR, "sources.json")                  # 记住上次可用的源，下次优先用

_lock = threading.Lock()
_last_hit = {}
_http_cache = {}
_session_obj = None


def _rel(path):
    """安全地转相对路径（Windows 上跨盘符时 os.path.relpath 会抛异常，这里兜底）"""
    try:
        return os.path.relpath(path, REPO_DIR)
    except Exception:
        return path


def _get_session():
    global _session_obj
    if _session_obj is None:
        _session_obj = requests.Session()
    return _session_obj


def _load_json(path, default):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return default


def _save_json(path, obj):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=1)
        os.replace(tmp, path)
    except Exception as exc:
        log("STATE", f"写入 {path} 失败: {exc}")


# 载入上次的 HTTP 缓存，让 ETag/Last-Modified 条件请求跨运行生效（重复运行几乎零真实请求）
_http_cache = _load_json(HTTP_CACHE_PATH, {})
if _http_cache:
    log("STATE", "已载入 HTTP 缓存 %d 条（将使用 304 条件请求，减少重复下载）" % len(_http_cache))


def _throttle(url):
    """同一域名两次请求之间保持最小间隔 + 随机抖动（人类节奏，不是机器节奏）"""
    host = (urlparse(url).netloc or url).lower()
    with _lock:
        wait = REQUEST_MIN_INTERVAL - (time.time() - _last_hit.get(host, 0.0))
        if wait > 0:
            time.sleep(wait + random.uniform(0, REQUEST_JITTER))
        _last_hit[host] = time.time()


class _CachedResponse(object):
    """304 命中本地缓存时用的轻量响应对象"""

    def __init__(self, text, status_code, url):
        self.text = text
        self.status_code = status_code
        self.url = url

    def json(self):
        return json.loads(self.text)

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("HTTP %s" % self.status_code)


def polite_get(url, session=None, timeout=None, headers=None, cache_ttl=1800, use_etag=True, max_retries=None):
    """
    礼貌 HTTP GET（[新增] 反风控核心）:
      1. 同域名限速 + 随机抖动
      2. ETag / Last-Modified 条件请求，服务器返回 304 时直接复用本地缓存
         —— 对 GitHub / VPN Gate 这类源，重复运行几乎不再产生真实请求
      3. 429 / 5xx / 网络异常时指数退避重试，并遵守 Retry-After
      4. 访问 api.github.com 时自动附带 GITHUB_TOKEN
         （匿名 60 次/小时 → 认证 5000 次/小时，避免因限流被判定为异常流量）
    """
    timeout = timeout or HTTP_TIMEOUT
    max_retries = MAX_RETRIES if max_retries is None else max_retries
    session = session or _get_session()
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    if GITHUB_TOKEN and "api.github.com" in url:
        hdrs["Authorization"] = "Bearer %s" % GITHUB_TOKEN

    st = _http_cache.get(url) or {}
    # 只有缓存过正文时才发条件请求（大文件不缓存正文，避免把 state 撑大）
    if use_etag and st.get("text") is not None:
        if st.get("etag"):
            hdrs["If-None-Match"] = st["etag"]
        if st.get("last_modified"):
            hdrs["If-Modified-Since"] = st["last_modified"]

    last_exc = None
    for attempt in range(max_retries + 1):
        _throttle(url)
        try:
            resp = session.get(url, timeout=timeout, headers=hdrs)
            if resp.status_code == 304 and st.get("text") is not None:
                log("HTTP", "304 未变化，使用本地缓存: %s" % url)
                return _CachedResponse(st["text"], 304, url)
            if resp.status_code in (429, 500, 502, 503, 504) and attempt < max_retries:
                ra = resp.headers.get("Retry-After") or ""
                delay = float(ra) if ra.isdigit() else BACKOFF_BASE ** (attempt + 1)
                log("HTTP", "HTTP %s，退避 %.1fs 后重试: %s" % (resp.status_code, delay, url))
                time.sleep(min(delay, 60) + random.uniform(0, 1.0))
                continue
            resp.raise_for_status()
            body = resp.text
            if len(body) <= HTTP_CACHE_MAX_BODY:
                _http_cache[url] = {
                    "ts": time.time(),
                    "etag": resp.headers.get("ETag"),
                    "last_modified": resp.headers.get("Last-Modified"),
                    "text": body,
                }
            else:
                # 响应太大（例如 VPN Gate 的 CSV/JSON），只记时间戳，不缓存正文
                _http_cache[url] = {"ts": time.time(), "too_large": len(body)}
            return resp
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                time.sleep(BACKOFF_BASE ** (attempt + 1) + random.uniform(0, 1.0))
    raise last_exc if last_exc else RuntimeError("请求失败: %s" % url)


def _tcp_probe(host_port, timeout=None):
    """对优选入口做一次 TCP 连接测试，成功返回毫秒延迟，失败返回 None"""
    timeout = timeout or ENDPOINT_TIMEOUT
    host, _, port = host_port.rpartition(":")
    host = host or host_port
    try:
        port = int(port or 443)
    except Exception:
        port = 443
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t0 = time.time()
    try:
        sock.connect((host, port))
        return int((time.time() - t0) * 1000)
    except Exception:
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def discover_vpngate_sources():
    """
    [新增] 自动发现 VPN Gate 官方镜像 + 多静态源:
      1. 先读上一次运行确认可用的源（state/sources.json，优先复用，避免重复试探）
      2. 再抓官方站点页面，正则提取候选镜像 / API 地址（自动发现）
      3. 与静态源列表合并去重
    """
    static = [s.strip() for s in (os.environ.get("VPNGATE_SOURCES") or "").split(",") if s.strip()]
    if not static:
        static = list(VPNGATE_STATIC_SOURCES)
    remembered = (_load_json(SOURCES_PATH, {}) or {}).get("vpngate_ok") or []
    discovered = []
    try:
        resp = polite_get("https://www.vpngate.net/en/", timeout=25, cache_ttl=6 * 3600)
        skip_hosts = ("twitter.com", "x.com", "facebook.com", "youtube.com", "instagram.com",
                      "t.me", "telegram", "linkedin.com", "reddit.com")
        for m in re.finditer(r"https?://[A-Za-z0-9\.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-/\.]*)?", resp.text):
            u = m.group(0).rstrip("/")
            if any(s in u.lower() for s in skip_hosts):
                continue
            if ("vpngate" in u or "/api/iphone" in u) and u not in discovered:
                discovered.append(u)
            if len(discovered) >= 5:
                break
        log("VPN GATE", "官方页面自动发现 %d 个候选镜像地址" % len(discovered))
    except Exception as exc:
        log("VPN GATE", "镜像自动发现失败（不影响主流程）: %s" % str(exc)[:100])

    ordered, seen = [], set()
    for u in (remembered + static + discovered):
        if u and u not in seen:
            seen.add(u)
            ordered.append(u)
    log("VPN GATE", "候选数据源 %d 个（记忆 %d / 静态 %d / 页面发现 %d）"
        % (len(ordered), len(remembered), len(static), len(discovered)))
    return ordered


def fetch_optimal_api_endpoints_auto(api_urls_str):
    """
    [新增] 多源自动获取优选入口:
      1. 依次请求配置的优选 API（失败自动用 OPTIMAL_API_FALLBACKS 兜底）
      2. 去重
      3. 本地 TCP 验证，只保留真正连得上的
      4. 按延迟从低到高排序，只留前 MAX_EDGE_ENDPOINTS 个
    """
    urls = [u.strip() for u in (api_urls_str or "").split(",") if u.strip()]
    if not urls:
        urls = list(OPTIMAL_API_FALLBACKS)
    raw = fetch_optimal_api_endpoints(",".join(urls))
    uniq, seen = [], set()
    for e in raw:
        if e and e not in seen:
            seen.add(e)
            uniq.append(e)
    if not uniq:
        log("OPTIMAL API", "所有优选 API 都没有返回数据，回退到静态优选域名池")
        return []
    if not VALIDATE_ENDPOINTS:
        return uniq[:MAX_EDGE_ENDPOINTS]

    log("OPTIMAL API", "本地 TCP 验证 %d 个候选入口（超时 %.1fs，并发 16）" % (len(uniq), ENDPOINT_TIMEOUT))
    good = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        futs = {pool.submit(_tcp_probe, e): e for e in uniq}
        for fut in as_completed(futs):
            ms = fut.result()
            if ms is not None:
                good.append((futs[fut], ms))
    good.sort(key=lambda x: x[1])
    keep = good[:MAX_EDGE_ENDPOINTS]
    log("OPTIMAL API", "验证通过 %d 个，保留最快 %d 个（最快 %s）" % (
        len(good), len(keep), ("%d ms" % keep[0][1]) if keep else "无"))
    return [e for e, _ in keep]


# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
def fetch_vpngate():
    """
    [改写] 多源抓取 + 自动发现镜像 + 合并去重 + 记住可用源
      相比原来"主源失败才用镜像"的做法，现在会把所有可用源的数据合并，
      节点更多、单点故障不影响整体，同时凑够 MAX_VPNGATE_SOURCES 个源就停止，
      多余的请求一个都不发（反风控）。
    """
    sources = discover_vpngate_sources()
    all_rows, ok_sources = [], []
    for src in sources:
        if len(ok_sources) >= MAX_VPNGATE_SOURCES:
            log("VPN GATE", "已凑够 %d 个可用源，停止尝试剩余源" % len(ok_sources))
            break
        is_json = src.endswith(".json") or "raw.githubusercontent" in src or "jsdelivr" in src or "data.json" in src
        try:
            if is_json:
                resp = polite_get(src, timeout=HTTP_TIMEOUT, cache_ttl=1800)
                rows = parse_mirror_json(resp.json())
            else:
                resp = polite_get(src, timeout=HTTP_TIMEOUT, cache_ttl=900)
                rows = parse_csv(resp.text)
            if rows:
                all_rows.extend(rows)
                ok_sources.append(src)
                log("VPN GATE", "  ✓ %s -> %d 行" % (src[:90], len(rows)))
            else:
                log("VPN GATE", "  ✗ %s -> 解析出 0 行" % src[:90])
        except Exception as exc:
            log("VPN GATE", "  ✗ %s -> %s" % (src[:90], str(exc)[:90]))

    if not all_rows:
        die("所有 VPN Gate 数据源都不可用（含官方 API、官方页面发现的镜像、GitHub 镜像）")

    dedup, seen = [], set()
    for r in all_rows:
        key = (str(r.get("host") or "").lower(), str(r.get("ip") or ""))
        if key in seen:
            continue
        seen.add(key)
        dedup.append(r)

    # 记住本次可用的源，下次优先使用（减少试探性请求）
    st = _load_json(SOURCES_PATH, {}) or {}
    st["vpngate_ok"] = ok_sources
    st["updated"] = time.time()
    _save_json(SOURCES_PATH, st)

    short = "+".join(s.split("/")[2] for s in ok_sources if "/" in s)
    log("VPN GATE", "合并 %d 个数据源: %d 行 -> 去重后 %d 个节点" % (len(ok_sources), len(all_rows), len(dedup)))
    return dedup, short

def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    header_idx = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            header_idx = i
            break
    if header_idx is None:
        raise RuntimeError("找不到 CSV 表头行 (HostName)")

    header = lines[header_idx].lstrip("#").split(",")
    data_lines = lines[header_idx + 1:]
    idx = {}
    for col in ("hostname", "ip", "countrylong", "countryshort", "openvpn_configdata_base64"):
        for i, h in enumerate(header):
            if h.strip().lstrip("*").lower() == col:
                idx[col] = i
                break
    if "openvpn_configdata_base64" not in idx:
        for i, h in enumerate(header):
            if "base64" in h.lower():
                idx["openvpn_configdata_base64"] = i
                break
    pos = {
        "hostname": idx.get("hostname", 0),
        "ip": idx.get("ip", 1),
        "countrylong": idx.get("countrylong", 5),
        "countryshort": idx.get("countryshort", 6),
        "openvpn_configdata_base64": idx.get("openvpn_configdata_base64", len(header) - 1),
    }

    rows = []
    for ln in data_lines:
        fields = next(csv.reader(io.StringIO(ln)))
        if len(fields) < 7: continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": fields[pos["countrylong"]].strip(),
            "country_short": fields[pos["countryshort"]].strip(),
            "config_b64": fields[pos["openvpn_configdata_base64"]].strip(),
        })
    return rows

def parse_mirror_json(data):
    servers = []
    items = data if isinstance(data, list) else [data]
    for item in items:
        if isinstance(item, dict) and isinstance(item.get("servers"), list):
            servers.extend(item["servers"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or "").strip()
        ip = str(s.get("ip") or "").strip()
        if not host or not ip: continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or "").strip(),
        })
    return rows

# ---------------------------------------------------------------------------
# 优选 API 获取与解析
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    """
    拉取优选 API，解析如: 172.66.1.179:443#CF 电信优选 格式的内容
    提取出纯 'IP:端口' (例如 172.66.1.179:443)
    """
    if not api_urls_str.strip():
        return []
    
    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            resp = polite_get(url, timeout=15, cache_ttl=600)
            if resp.status_code in (200, 304):
                before = len(endpoints)
                # 方式一: 逐行 "IP:端口#备注" 格式
                for line in resp.text.strip().splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    endpoint = line.split("#")[0].strip()
                    if endpoint:
                        if ":" not in endpoint:
                            endpoint = f"{endpoint}:443"
                        endpoints.append(endpoint)
                got = len(endpoints) - before
                # 方式二(兜底): HTML 榜单等任意文本，正则抠出全部 IPv4[:端口]，后续由本地 TCP 验证筛掉无效项
                if got == 0:
                    for m in re.finditer(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b", resp.text):
                        ip = m.group(1)
                        if ip.startswith(("0.", "127.", "10.", "192.168.", "169.254.")):
                            continue
                        endpoints.append("%s:%s" % (ip, m.group(2) or "443"))
                    got = len(endpoints) - before
                log("OPTIMAL API", f"成功从 API 获取到 {got} 个优选端点")
            else:
                log("OPTIMAL API", f"API 返回状态码异常: {resp.status_code}")
        except Exception as e:
            log("OPTIMAL API", f"拉取优选 API 失败 ({url}): {e}")
    return endpoints

def get_combined_edge_hosts():
    """
    合并静态优选域名与优选 API 端点
    """
    # 1. 优先读取 HOSTS_ENTRY 或 EDGE_HOSTS
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS

    # 2. 自动拉取优选 API 端点（多源兜底 + 本地 TCP 验证 + 按延迟排序）
    api_hosts = fetch_optimal_api_endpoints_auto(OPTIMAL_API)

    # 3. 合并与去重 (保留原始列表顺序)
    combined = []
    seen = set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)

    log("EDGE POOL", f"汇总入口地址池: 静态域名 {len(static_hosts)} 个, API 获取 {len(api_hosts)} 个, 合并有效入口共 {len(combined)} 个")
    return combined if combined else EDGE_HOSTS

# ---------------------------------------------------------------------------
# 筛选 SSTP 节点
# ---------------------------------------------------------------------------
_PROTO_TCP_RE = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
_REMOTE_RE = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)

def to_sstp_nodes(rows):
    nodes = []
    for r in rows:
        cfg = ""
        if r["config_b64"]:
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not _PROTO_TCP_RE.search(cfg): continue
        m = _REMOTE_RE.search(cfg)
        if not m: continue
        port = int(m.group(1))
        if not (1 <= port <= 65535): continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({"host": host, "port": port, "ip": r["ip"], "country": r["country_long"], "country_code": r["country_short"]})
    return nodes

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen: continue
        seen.add(key)
        out.append(n)
    return out

# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True: return "datacenter"
    if is_datacenter is False: return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS): return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS): return "residential"
    h = host.lower()
    if h.startswith("public-vpn"): return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h): return "residential"
    return "unknown"

def check_one(node, session):
    url = WORKER_CHECK_URL + quote(f"{node['host']}:{node['port']}", safe="")
    out = dict(node)
    out["protocol"] = "sstp"
    out["link"] = f"sstp://vpn:vpn@{node['host']}:{node['port']}"
    out["status"] = "failed"
    out["checked_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out["exit"] = None
    out["residential"] = "unknown"
    try:
        r = session.get(url, timeout=CHECK_TIMEOUT, headers={"User-Agent": "Mozilla/5.0 (gate-checker)"})
        if r.status_code != 200:
            out["error"] = f"HTTP {r.status_code}"
            out["worker_error"] = True
            return out
        j = r.json()
        ok = bool(j.get("success"))
        out["success"] = ok
        out["status"] = "success" if ok else "failed"
        out["latency_ms"] = j.get("responseTime")
        out["colo"] = j.get("colo")
        out["error"] = (None if ok else (j.get("error") or j.get("message") or "check failed"))
        exit_info = j.get("exit") or {}
        if exit_info:
            asn = exit_info.get("asn") or {}
            org = asn.get("org") or asn.get("name") or ""
            out["exit"] = {
                "ip": exit_info.get("ip"),
                "country": exit_info.get("country"),
                "country_code": exit_info.get("country_code"),
                "city": exit_info.get("city"),
                "continent": exit_info.get("continent"),
                "asn": asn.get("asn"),
                "org": org,
                "type": asn.get("type"),
                "is_datacenter": exit_info.get("is_datacenter"),
            }
            out["residential"] = classify_network(out["host"], org, exit_info.get("is_datacenter"))
        else:
            out["residential"] = classify_network(out["host"], None, None)
        return out
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        out["worker_error"] = True
        return out

def check_all(nodes, session):
    """
    [新增] 三层减负检测（反风控关键）:
      1. 结果缓存: CHECK_CACHE_TTL 秒内检测过的节点直接复用，不重复请求 Worker
         —— 定时任务跑得越勤，省下的请求越多（这是降低 Cloudflare 请求量最有效的办法）
      2. 分批提交: 每批 CONCURRENCY 个，批间 sleep，避免瞬时并发被 WAF 拦
      3. 检测结果落盘 state/check_cache.json，下次运行可复用
    """
    cache = _load_json(CHECK_CACHE_PATH, {})
    now = time.time()
    results, todo, reused = [], [], 0
    for n in nodes:
        key = "%s:%s" % (n.get("host"), n.get("port"))
        item = cache.get(key) or {}
        if item and (now - float(item.get("ts") or 0)) < CHECK_CACHE_TTL:
            row = dict(n)
            row.update(item.get("result") or {})
            results.append(row)
            reused += 1
        else:
            todo.append(n)
    if reused:
        log("CLOUDFLARE WORKER", "命中缓存 %d 个节点（%d 小时内检测过，直接复用，不重复请求）" % (reused, CHECK_CACHE_TTL // 3600))
    log("CLOUDFLARE WORKER", "本次需要真实检测: %d 个（并发 %d，批间隔 %.1fs）" % (len(todo), CONCURRENCY, CHECK_BATCH_DELAY))

    for i in range(0, len(todo), CONCURRENCY):
        batch = todo[i:i + CONCURRENCY]
        with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
            futs = [pool.submit(check_one, n, session) for n in batch]
            for fut in as_completed(futs):
                results.append(fut.result())
        done = min(i + CONCURRENCY, len(todo))
        if done < len(todo):
            log("CLOUDFLARE WORKER", "进度 %d/%d" % (done, len(todo)))
            time.sleep(CHECK_BATCH_DELAY + random.uniform(0, 0.5))

    fields = ("success", "status", "latency_ms", "colo", "error", "exit", "residential",
              "checked_at", "country", "country_code", "protocol", "link")
    for r in results:
        if r.get("worker_error"):
            continue
        key = "%s:%s" % (r.get("host"), r.get("port"))
        cache[key] = {"ts": now, "result": dict((k, r.get(k)) for k in fields)}
    _save_json(CHECK_CACHE_PATH, cache)
    return results

# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]
    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len(available),
        "failed": len(results) - len(available),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
    }
    by_country = {}
    for name, grp in countries.items():
        grp["count"] = len(grp["nodes"])
        grp["residential"] = sum(1 for n in grp["nodes"] if n["residential"] == "residential")
        grp["datacenter"] = sum(1 for n in grp["nodes"] if n["residential"] == "datacenter")
        grp["nodes"].sort(key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n["host"]))
        by_country[name] = grp

    data = {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "source": source,
        "worker": WORKER_CHECK_URL,
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data

def build_nodes_text(data, edge_hosts):
    """
    生成纯节点行版本 (无注释): 每行 = 入口地址#名字$sstp://...
    """
    countries = data["countries"]
    edge = edge_hosts
    lines = []
    idx = 0
    ordered = sorted(countries.items(), key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0])))
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(grp["nodes"], key=lambda n: (0 if n.get("residential") == "residential" else 1, n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("host") or ""))
        res_nodes = [n for n in nodes if n.get("residential") == "residential"]
        # [新增] KEEP_RESIDENTIAL_ONLY=1 时只输出住宅节点，机房节点全部丢弃
        dc_nodes = [] if KEEP_RESIDENTIAL_ONLY else [n for n in nodes if n.get("residential") != "residential"]
        for i, n in enumerate(res_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
        for i, n in enumerate(dc_nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-机房-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
    return "\n".join(lines) + "\n"

def write_outputs(data, edge_hosts):
    os.makedirs(PUBLIC_DIR, exist_ok=True)
    data_path = os.path.join(PUBLIC_DIR, "data.json")
    with open(data_path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)

    html_path = os.path.join(PUBLIC_DIR, "index.html")
    if os.path.exists(TEMPLATE_HTML):
        with open(TEMPLATE_HTML, "r", encoding="utf-8") as f:
            html = f.read()
    else:
        html = (
            "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 节点</title></head>"
            "<body><h1>VPN Gate SSTP 节点</h1><pre id='out'></pre></body>"
            "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats)).catch(e=>out.textContent='加载失败:'+e)</script></html>"
        )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    nodes_text = build_nodes_text(data, edge_hosts)
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(nodes_text)

    return data_path, html_path, nodes_path, nodes_text

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点 (数据源异常, 不允许生成空结果)")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点 — 数据格式可能已变化, 需要人工适配")
    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)}")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 单请求超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (其中 Worker 异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常, 检测服务不可用 — 本次运行判定失败 (不生成空结果)")

    # ---- [新增] 住宅节点留存库：历史验证过的好节点，不会被单次检测抖动丢掉 ----
    keep = _load_json(KEEP_PATH, {})
    cutoff = time.time() - RESIDENTIAL_KEEP_DAYS * 86400
    for k in list(keep.keys()):
        if float((keep.get(k) or {}).get("last_ok") or 0) < cutoff:
            keep.pop(k, None)
    for r in results:
        if r.get("success") and r.get("residential") == "residential":
            keep["%s:%s" % (r.get("host"), r.get("port"))] = {
                "last_ok": time.time(),
                "host": r.get("host"),
                "port": r.get("port"),
                "country": r.get("country"),
                "country_code": r.get("country_code"),
                "latency_ms": r.get("latency_ms"),
                "exit": r.get("exit"),
                "residential": "residential",
            }
    have = set("%s:%s" % (r.get("host"), r.get("port")) for r in results)
    merged = 0
    for key, item in keep.items():
        if key in have:
            continue
        restored = dict(item)
        restored.update({
            "success": True,
            "status": "success",
            "from_keep": True,
            "error": None,
            "checked_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        })
        results.append(restored)
        merged += 1
    _save_json(KEEP_PATH, keep)
    log("RESIDENTIAL", "住宅留存库 %d 个；本次从留存库补回 %d 个（保留 %d 天）" % (len(keep), merged, RESIDENTIAL_KEEP_DAYS))

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"可用节点: {len([r for r in results if r.get('success')])}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    # 动态拉取 API 并与静态优选域名混合
    edge_hosts = get_combined_edge_hosts()

    data_path, html_path, nodes_path, nodes_text = write_outputs(data, edge_hosts)
    log("WEBSITE", f"生成 {_rel(data_path)}")
    log("WEBSITE", f"生成 {_rel(html_path)}")
    log("WEBSITE", f"生成 {_rel(nodes_path)}")
    log("USAGE", f"自动轮换: 把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」框 (一次配置, 之后自动更新)")

    # ---- [新增] 内容指纹：内容没变就不提交，避免在 GitHub 上刷出海量无意义 commit ----
    _save_json(HTTP_CACHE_PATH, _http_cache)
    rev_path = os.path.join(PUBLIC_DIR, "rev.txt")
    rev = hashlib.sha256((json.dumps(data, ensure_ascii=False, sort_keys=True) + nodes_text).encode("utf-8")).hexdigest()[:16]
    old_rev = ""
    try:
        with open(rev_path, "r", encoding="utf-8") as fh:
            old_rev = fh.read().strip()
    except Exception:
        old_rev = ""
    with open(rev_path, "w", encoding="utf-8") as fh:
        fh.write(rev + "\n")
    changed = (old_rev != rev)
    log("CHANGE", "内容指纹 %s（上次 %s）→ %s" % (rev, old_rev or "无", "有变化，需要提交" if changed else "无变化，跳过提交"))
    print("OUTPUT_CHANGED=%d" % (1 if changed else 0))
    log("WEBSITE", "完成 (GitHub Pages 部署由 workflow 执行)")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
