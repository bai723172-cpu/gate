#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
build_nodes.py —— 自动抓取 VPN Gate 住宅节点 → 验证 → 剔除不合格 → 生成节点清单
=================================================================================
每天由 GitHub Actions 自动运行一次。特点：
  1. 多数据源（官方 API + 多个国内可直连的镜像），任一可用即可，全部失败则保留上一版结果
  2. 只保留 SSTP(TCP) 节点
  3. 判定国家（国旗 + 中文名）与住宅/机房（依据官方 Operator 字段 + 主机名规则）
  4. 逐个验证：TCP 连通 + TLS 握手（SSTP 以 TLS 开头，握手成功说明服务在线）
     —— 用节点自身 IP 连接，绕开 *.opengw.net 的 DNS 问题
  5. 剔除不合格节点（连不通 / TLS 失败），输出 edgetunnel 可直接消费的 nodes.txt
  6. 输出变化时才让工作流提交，避免无意义的提交

输出（写入 public/）：
  nodes.txt    edgetunnel「自定义优选IP」用：入口域名:443#国家-住宅-01$sstp://vpn:vpn@IP:端口
  data.json    结构化数据（节点明细 + 统计）
  index.html   一个简单的结果页（可选，方便浏览器查看）
"""

import base64
import csv
import io
import json
import os
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
    print("缺少 requests，请先 pip install requests")
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(BASE_DIR, "public")

# --------------------------------------------------------------------------
# 配置
# --------------------------------------------------------------------------
# --------------------------------------------------------------------------
# 数据源
#   ① 官方 API（数据最全，优先）
#   ② 自动发现：抓官方页面，提取里面出现的镜像地址
#   ③ 静态镜像：多个已验证的镜像/加速地址（互为备份）
# --------------------------------------------------------------------------
OFFICIAL_SOURCES = [
    ("official-tls", "https://www.vpngate.net/api/iphone/", "csv"),
    ("official",     "http://www.vpngate.net/api/iphone/", "csv"),
]
DISCOVER_PAGES = [
    "https://www.vpngate.net/en/",
    "https://www.vpngate.net/ja/",
    "https://www.vpngate.net/cn/",
]
STATIC_MIRRORS = [
    ("gh-proxy",    "https://gh-proxy.com/https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json", "json"),
    ("jsdelivr-gc", "https://gcore.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json", "json"),
    ("jsdelivr-fs", "https://fastly.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json", "json"),
    ("jsdelivr-tc", "https://testingcf.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json", "json"),
    ("ghproxy.net", "https://ghproxy.net/https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json", "json"),
    ("jsdelivr-cd", "https://cdn.jsdelivr.net/gh/fdciabdul/Vpngate-Scraper-API@main/json/data.json", "json"),
    ("github-raw",  "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json", "json"),
    ("ghfast",      "https://ghfast.top/https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json", "json"),
    ("gh-llkk",     "https://gh.llkk.cc/https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json", "json"),
    ("githack",     "https://raw.githack.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json", "json"),
    # 官方 API 的备用写法
    ("official-www", "https://www.vpngate.net/api/iphone", "csv"),
    ("vpngate-net",  "https://vpngate.net/api/iphone/", "csv"),
]
MAX_SOURCES = 8              # 最多用这么多个可用源（官方源总是会被尝试）
KEEP_RESIDENTIAL_ONLY = True # 只保留住宅节点
CHECK_CONCURRENCY = 32       # 并发验证数
CHECK_TIMEOUT = 8            # 单个节点验证超时（秒）
MIN_KEEP = 10                # 验证后至少保留这么多，否则放宽条件（避免产出空列表）
MAX_NODES = 150              # 最终最多保留多少个（按延迟从快到慢取）
MAX_LATENCY_MS = 3000        # 延迟超过这个值的算「不合格」（TLS 成功但太慢的剔除）
# 本机（墙内）测试用：设置环境变量 CHECK_PROXY=127.0.0.1:3067 即可经代理验证
# GitHub Actions 上不需要设置（那边本身就在墙外，直连验证即可）
CHECK_PROXY = os.environ.get("CHECK_PROXY", "").strip()
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NodesBot/1.0"

# edgetunnel 的优选入口（客户端会用它做入口，实际路由按订阅里的 Host 走）
EDGE_HOSTS = [
    "saas.sin.fan", "cdn.204910.best", "www.mfyx.cn", "p.etime.vip",
    "cf.877774.xyz", "cf.nyanya.moe", "www.sloomb.com", "op.chinwa.eu.cc",
    "www.shopify.com", "www.carousell.sg", "www.dbs.com.sg", "openai.com",
    "linear.app", "www.bilibili.com", "uspto.gov", "www.vmware.com",
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
    "EG": "埃及", "HR": "克罗地亚", "BY": "白俄罗斯", "MD": "摩尔多瓦",
    "RS": "塞尔维亚", "BG": "保加利亚", "SK": "斯洛伐克", "SI": "斯洛文尼亚",
    "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚", "GE": "格鲁吉亚",
    "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦", "MN": "蒙古", "NP": "尼泊尔",
    "MM": "缅甸", "KH": "柬埔寨", "LA": "老挝", "BD": "孟加拉", "PK": "巴基斯坦",
    "IR": "伊朗", "IQ": "伊拉克", "JO": "约旦", "LB": "黎巴嫩", "KW": "科威特",
    "QA": "卡塔尔", "OM": "阿曼", "CY": "塞浦路斯", "MT": "马耳他", "IS": "冰岛",
    "LU": "卢森堡", "BA": "波黑", "MK": "北马其顿", "AL": "阿尔巴尼亚",
    "ME": "黑山", "MO": "澳门", "BN": "文莱", "FJ": "斐济", "PR": "波多黎各",
    "CR": "哥斯达黎加", "PA": "巴拿马", "GT": "危地马拉", "DO": "多米尼加",
    "JM": "牙买加", "EC": "厄瓜多尔", "PE": "秘鲁", "BO": "玻利维亚",
    "PY": "巴拉圭", "UY": "乌拉圭", "VE": "委内瑞拉", "NG": "尼日利亚",
    "KE": "肯尼亚", "GH": "加纳", "TZ": "坦桑尼亚", "UG": "乌干达",
    "MA": "摩洛哥", "DZ": "阿尔及利亚", "TN": "突尼斯", "SN": "塞内加尔",
    "CI": "科特迪瓦", "CM": "喀麦隆", "AO": "安哥拉", "MZ": "莫桑比克",
    "ZW": "津巴布韦", "ZM": "赞比亚", "BW": "博茨瓦纳", "NA": "纳米比亚",
    "MU": "毛里求斯", "AZ": "阿塞拜疆", "AF": "阿富汗", "SY": "叙利亚",
    "YE": "也门", "TM": "土库曼斯坦", "TJ": "塔吉克斯坦", "KG": "吉尔吉斯斯坦",
}

DATA_CENTER_KEYWORDS = [
    "GOOGLE", "AMAZON", "AWS", "MICROSOFT", "AZURE", "OVH", "HETZNER", "DIGITALOCEAN",
    "AKAMAI", "CLOUDFLARE", "FASTLY", "RACKSPACE", "EQUINIX", "LINODE", "VULTR",
    "HURRICANE", "TENCENT", "ALIBABA", "ALIYUN", "LEASEWEB", "CHOOPA", "M247",
    "DATACAMP", "CONTABO", "IONOS", "SCALEWAY", "ORACLE", "IBM", "COLOCROSSING",
    "SERVER", "HOSTING", "DATACENTER", "DATA CENTER", "IDC", "CLOUD", "VPN SERVER",
    "PUBLIC VPN", "VPNGATE", "SOFTLAYER", "G-CORE", "GLOBALLAYER", "CDN77",
    "QUANTIL", "EDGECAST", "STACKPATH", "BUNNY", "BACKBLAZE",
]
RESIDENTIAL_KEYWORDS = [
    "NTT", "KDDI", "SOFTBANK", "DOCOMO", "J:COM", "JCOM", "OCN", "BIGLOBE", "IIJ",
    "PLALA", "SO-NET", "NURO", "HIKARI", "COMCAST", "XFINITY", "AT&T", "VERIZON",
    "CENTURYLINK", "CHARTER", "COX", "SPECTRUM", "FRONTIER", "WINDSTREAM",
    "TELUS", "ROGERS", "BELL", "SHAW", "VIDEOTRON", "DEUTSCHE TELEKOM", "VODAFONE",
    "ORANGE", "TELEFONICA", "TELIA", "TELENOR", "VIRGIN MEDIA", "PLUSNET",
    "CHINA TELECOM", "CHINA UNICOM", "CHINA MOBILE", "CMCC", "CHINANET",
    "KOREA TELECOM", "SK BROADBAND", "LG U+", "HELLOVISION", "CHUNGHWA", "HINET",
    "SEEDNET", "SINGTEL", "STARHUB", "MYREPUBLIC", "TTNET", "TURK TELEKOM",
    "SUPERONLINE", "ROSTELECOM", "BEELINE", "ZIGGO", "KPN", "T-MOBILE",
    "PROXIMUS", "SWISSCOM", "INIT7", "SUNRISE", "MAGENTA", "FASTWEB",
    "FREE FRANCE", "CLARO", "VIVO", "TELMEX", "BHARTI", "AIRTEL", "JIO", "BSNL",
    "MTN", "TELKOM", "SAFARICOM", "OPTUS", "TELSTRA", "TPG", "IINET", "SPARK NZ",
    "TELECOM", "COMMUNICATION", "BROADBAND", "CABLE",
]

TZ_CN = timezone(timedelta(hours=8))


def log(msg):
    print(msg, flush=True)


def flag_of(code):
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def country_name(code, fallback=""):
    code = (code or "").strip().upper()
    return COUNTRY_ZH.get(code) or (fallback or code or "未知")


# --------------------------------------------------------------------------
# 1. 抓取
# --------------------------------------------------------------------------
def discover_mirrors(session):
    """自动发现：抓官方页面，把里面出现的镜像/API 地址找出来"""
    found = []
    skip = ("twitter.com", "x.com", "facebook.com", "youtube.com", "instagram.com",
            "t.me", "telegram", "linkedin.com", "reddit.com", "github.com/cmliu",
            "wikipedia", "creativecommons", ".png", ".jpg", ".css", ".js", "mailto")
    for page in DISCOVER_PAGES:
        try:
            r = session.get(page, timeout=20)
            if r.status_code != 200:
                log("  - 发现页 %-34s HTTP %s" % (page.replace("https://", ""), r.status_code))
                continue
            cnt = 0
            for m in re.finditer(r"https?://[A-Za-z0-9\.\-]+(?::\d+)?(?:/[A-Za-z0-9_\-/\.]*)?", r.text):
                u = m.group(0).rstrip("/")
                low = u.lower()
                if any(s in low for s in skip):
                    continue
                if not ("vpngate" in low or "opengw" in low or "/api/iphone" in low):
                    continue
                if u in found or u in [x[1] for x in OFFICIAL_SOURCES]:
                    continue
                found.append(u)
                cnt += 1
                if cnt >= 6:
                    break
            log("  + 发现页 %-34s 提取到 %d 个候选" % (page.replace("https://", ""), cnt))
        except Exception as exc:
            log("  - 发现页 %-34s %s" % (page.replace("https://", ""), str(exc)[:50]))
    return found


def collect_sources(session):
    """汇总所有数据源：官方优先 → 自动发现 → 静态镜像"""
    out = list(OFFICIAL_SOURCES)
    names = set(n for n, _, _ in out)
    for i, u in enumerate(discover_mirrors(session)):
        kind = "json" if ("json" in u or "jsdelivr" in u or "raw.github" in u or "gh-proxy" in u) else "csv"
        nm = "discovered-%d" % (i + 1)
        if nm not in names:
            out.append((nm, u, kind))
            names.add(nm)
    for item in STATIC_MIRRORS:
        if item[1] not in [x[1] for x in out]:
            out.append(item)
    log("数据源共 %d 个（官方 %d + 发现 %d + 静态 %d）"
        % (len(out), len(OFFICIAL_SOURCES), len(out) - len(OFFICIAL_SOURCES) - len(STATIC_MIRRORS), len(STATIC_MIRRORS)))
    return out


def fetch_rows():
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    rows, usable = [], []
    seen_fp = set()
    sources = collect_sources(session)
    for name, url, kind in sources:
        if len(usable) >= MAX_SOURCES:
            log("已凑够 %d 个可用源，停止尝试" % len(usable))
            break
        try:
            t0 = time.time()
            r = None
            for attempt in (1, 2):                      # 失败重试一次，抗网络抖动
                try:
                    r = session.get(url, timeout=25)
                    if r.status_code == 200:
                        break
                except Exception:
                    if attempt == 2:
                        raise
                    time.sleep(1.0)
            if r is None or r.status_code != 200:
                log("  x %-12s HTTP %s" % (name, getattr(r, "status_code", "?")))
                continue
            if kind == "json":
                data = r.json()
                servers = []
                for item in (data if isinstance(data, list) else [data]):
                    if isinstance(item, dict) and isinstance(item.get("servers"), list):
                        servers.extend(item["servers"])
                    elif isinstance(item, dict):
                        servers.append(item)
                got = []
                for s in servers:
                    host = str(s.get("hostname") or s.get("host") or "").strip()
                    ip = str(s.get("ip") or "").strip()
                    if host and ip:
                        got.append({
                            "host": host, "ip": ip,
                            "country_long": str(s.get("countrylong") or s.get("country") or ""),
                            "country_short": str(s.get("countryshort") or s.get("country_short") or ""),
                            "operator": str(s.get("operator") or ""),
                            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or ""),
                            "sessions": str(s.get("numvpnsessions") or ""),
                            "speed": str(s.get("speed") or ""),
                        })
            else:
                got = parse_csv(r.text)
            if got:
                fp = hash(tuple(sorted((r0["host"].lower(), r0["ip"]) for r0 in got)))
                rows.extend(got)
                if fp in seen_fp:
                    # 同一个镜像的不同加速地址，内容一样 -> 合并数据但不重复计数
                    log("  = %-12s %d 行（内容与前面某个源相同，不重复计数）" % (name, len(got)))
                else:
                    seen_fp.add(fp)
                    usable.append(name)
                    log("  v %-12s %d 行 (%.1fs)" % (name, len(got), time.time() - t0))
            else:
                log("  x %-12s 解析出 0 行" % name)
        except Exception as exc:
            log("  x %-12s %s" % (name, str(exc)[:60]))
    if not rows:
        return [], []
    # 去重
    seen, uniq = set(), []
    for r0 in rows:
        k = (r0["host"].lower(), r0["ip"])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(r0)
    log("合并 %d 个源 / %d 行 -> 去重 %d 个" % (len(usable), len(rows), len(uniq)))
    return uniq, usable


def parse_csv(text):
    lines = [ln for ln in text.splitlines() if ln.strip()]
    hi = None
    for i, ln in enumerate(lines):
        if ln.lstrip("#").startswith("HostName"):
            hi = i
            break
    if hi is None:
        return []
    header = [h.strip().lstrip("*").lower() for h in lines[hi].lstrip("#").split(",")]
    idx = {}
    for key in ("hostname", "ip", "countrylong", "countryshort", "operator",
                "numvpnsessions", "speed", "openvpn_configdata_base64"):
        if key in header:
            idx[key] = header.index(key)
    if not idx:
        for i, h in enumerate(header):
            if "base64" in h:
                idx["openvpn_configdata_base64"] = i
    out = []
    for ln in lines[hi + 1:]:
        if ln.startswith("*"):
            continue
        try:
            f = next(csv.reader(io.StringIO(ln)))
        except Exception:
            continue
        if len(f) < 7:
            continue

        def pick(k):
            i = idx.get(k)
            return f[i].strip() if (i is not None and i < len(f)) else ""

        if pick("hostname") and pick("ip"):
            out.append({
                "host": pick("hostname"), "ip": pick("ip"),
                "country_long": pick("countrylong"), "country_short": pick("countryshort"),
                "operator": pick("operator"), "config_b64": pick("openvpn_configdata_base64"),
                "sessions": pick("numvpnsessions"), "speed": pick("speed"),
            })
    return out


# --------------------------------------------------------------------------
# 2. 解析 SSTP + 分类
# --------------------------------------------------------------------------
PROTO_TCP = re.compile(r"^proto\s+(tcp|tcp4|tcp6)\b", re.M)
REMOTE_PORT = re.compile(r"^remote\s+\S+\s+(\d+)", re.M)


def to_sstp(rows):
    out = []
    for r in rows:
        cfg = ""
        if r.get("config_b64"):
            try:
                cfg = base64.b64decode(r["config_b64"], validate=False).decode("utf-8", "replace")
            except Exception:
                cfg = ""
        if not PROTO_TCP.search(cfg):
            continue
        m = REMOTE_PORT.search(cfg)
        if not m:
            continue
        try:
            port = int(m.group(1))
        except ValueError:
            continue
        if not (1 <= port <= 65535):
            continue
        code = (r.get("country_short") or "").strip().upper()
        out.append({
            "host": r["host"], "ip": r["ip"], "port": port,
            "country_code": code,
            "country": country_name(code, r.get("country_long", "")),
            "flag": flag_of(code),
            "operator": r.get("operator", ""),
            "sessions": r.get("sessions", ""),
            "speed": r.get("speed", ""),
        })
    return out


def classify(node):
    op = (node.get("operator") or "").upper()
    host = (node.get("host") or "").lower()
    for k in DATA_CENTER_KEYWORDS:
        if k in op:
            return "datacenter"
    for k in RESIDENTIAL_KEYWORDS:
        if k in op:
            return "residential"
    if host.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", host) or re.match(r"^vpnv\d+", host):
        return "residential"     # 志愿者家用电脑的命名特征
    if op:
        return "residential" if any(x in op for x in ("TELECOM", "COMMUNICATION", "BROADBAND", "CABLE", "NET")) else "unknown"
    return "unknown"


# --------------------------------------------------------------------------
# 3. 验证（TCP + TLS 握手）
# --------------------------------------------------------------------------
def verify_via_connect(node, timeout=CHECK_TIMEOUT):
    """经 HTTP 代理的 CONNECT 测试（本机在墙内时用；GitHub Actions 上不用）"""
    p = CHECK_PROXY.replace("http://", "").replace("https://", "").strip("/")
    host, _, port = p.rpartition(":")
    if host:
        try:
            port = int(port)
        except ValueError:
            host, port = "127.0.0.1", 3067
    else:
        host, port = "127.0.0.1", 3067
    s = socket.socket()
    s.settimeout(timeout)
    t0 = time.time()
    try:
        s.connect((host, port))
        req = "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n" % (
            node["ip"], node["port"], node["ip"], node["port"])
        s.sendall(req.encode())
        buf = b""
        while b"\r\n" not in buf and len(buf) < 1024:
            c = s.recv(256)
            if not c:
                break
            buf += c
        if b" 200" in buf.split(b"\r\n")[0]:
            return (True, int((time.time() - t0) * 1000), "proxy-ok")
        return (False, None, "proxy-fail")
    except Exception:
        return (False, None, "proxy-fail")
    finally:
        try:
            s.close()
        except Exception:
            pass


def _verify_once(node, timeout=CHECK_TIMEOUT):
    """用节点 IP 做 TCP 连接 + TLS 握手。
       SSTP 以 TLS 开头，握手成功说明该节点服务在线 —— 这才是「合格」的判据。"""
    if CHECK_PROXY:
        return verify_via_connect(node, timeout)
    tcp_ms = tls_ms = None
    s = None
    t0 = time.time()
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((node["ip"], node["port"]))
        tcp_ms = int((time.time() - t0) * 1000)
    except Exception:
        try:
            s and s.close()
        except Exception:
            pass
        return (False, None, "tcp-fail")
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        t1 = time.time()
        with ctx.wrap_socket(s, server_hostname=node["host"]) as ts:
            ts.settimeout(timeout)
            try:
                ts.do_handshake()
            except Exception:
                pass
        tls_ms = int((time.time() - t1) * 1000)
        return (True, tcp_ms, "tls-ok")
    except Exception:
        try:
            s.close()
        except Exception:
            pass
        return (True, tcp_ms, "tcp-only")   # TCP 通但 TLS 没成


def verify(node, timeout=CHECK_TIMEOUT, retries=1):
    """验证节点；失败/只通过 TCP 的重试一次（网络抖动很常见，重试明显提升合格率）"""
    ok, ms, how = _verify_once(node, timeout)
    tries = 0
    while tries < retries and how not in ("tls-ok", "proxy-ok"):
        tries += 1
        time.sleep(0.4)
        ok2, ms2, how2 = _verify_once(node, timeout)
        # 取更好的结果
        if how2 in ("tls-ok", "proxy-ok") or (ok2 and not ok):
            ok, ms, how = ok2, ms2, how2
    return (ok, ms, how)


def verify_all(nodes, log_fn=None):
    results = []
    done = [0]
    total = len(nodes)
    with ThreadPoolExecutor(max_workers=CHECK_CONCURRENCY) as pool:
        futs = {pool.submit(verify, n): n for n in nodes}
        for fut in as_completed(futs):
            n = futs[fut]
            try:
                ok, ms, how = fut.result()
            except Exception:
                ok, ms, how = False, None, "error"
            n = dict(n)
            n["alive"] = bool(ok)
            n["latency_ms"] = ms
            n["verify"] = how
            results.append(n)
            done[0] += 1
            if log_fn and (done[0] % 50 == 0 or done[0] == total):
                log_fn("  验证 %d/%d" % (done[0], total))
    return results


# --------------------------------------------------------------------------
# 4. 输出
# --------------------------------------------------------------------------
def group_by_country(nodes):
    g = {}
    for n in nodes:
        g.setdefault(n["country_code"] or "??", []).append(n)
    for c in g:
        g[c].sort(key=lambda x: (x.get("latency_ms") is None, x.get("latency_ms") or 99999))
    return dict(sorted(g.items(), key=lambda kv: (-len(kv[1]), kv[0])))


def build_nodes_txt(nodes):
    """只输出住宅节点（机房节点一律不写入 —— 用户要求「只要住宅 IP」）"""
    lines, idx = [], 0
    for code, grp in group_by_country(nodes).items():
        zh = country_name(code)
        res = [n for n in grp if n.get("kind") == "residential"]
        dc = [n for n in grp if n.get("kind") != "residential"]
        if dc and not KEEP_RESIDENTIAL_ONLY:
            log("   （同时输出 %d 个非住宅节点，因为它们没被过滤）" % len(dc))
        for i, n in enumerate(res, 1):
            e = EDGE_HOSTS[idx % len(EDGE_HOSTS)]
            idx += 1
            lines.append("%s:443#%s-住宅-%02d$sstp://vpn:vpn@%s:%d" % (e, zh, i, n["ip"], n["port"]))
        if KEEP_RESIDENTIAL_ONLY:
            continue                        # 硬保证：只有住宅 IP 会出现在清单里
        for i, n in enumerate(dc, 1):
            e = EDGE_HOSTS[idx % len(EDGE_HOSTS)]
            idx += 1
            lines.append("%s:443#%s-机房-%02d$sstp://vpn:vpn@%s:%d" % (e, zh, i, n["ip"], n["port"]))
    return "\n".join(lines) + ("\n" if lines else "")


def write_outputs(nodes, stats):
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(os.path.join(OUT_DIR, "nodes.txt"), "w", encoding="utf-8") as f:
        f.write(build_nodes_txt(nodes))
    data = {
        "updated_at": datetime.now(TZ_CN).strftime("%Y-%m-%d %H:%M:%S"),
        "stats": stats,
        "by_country": {c: len(g) for c, g in group_by_country(nodes).items()},
        "nodes": nodes,
    }
    with open(os.path.join(OUT_DIR, "data.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    html = ["<!DOCTYPE html><html lang=zh-CN><head><meta charset=utf-8>",
            "<title>住宅节点清单</title><style>body{font-family:sans-serif;max-width:900px;margin:24px auto;padding:0 16px}",
            "table{border-collapse:collapse;width:100%}td,th{border:1px solid #ddd;padding:6px 10px;font-size:14px}",
            "th{background:#f5f5f5}</style></head><body>",
            "<h2>住宅节点清单</h2><p>更新时间：%s</p>" % data["updated_at"],
            "<p>节点 %d 个（住宅 %d），覆盖 %d 个国家/地区</p>" % (
                stats["total"], stats["residential"], len(data["by_country"])),
            "<table><tr><th>国家</th><th>住宅</th><th>机房</th><th>最快延迟</th></tr>"]
    for c, g in group_by_country(nodes).items():
        best = min((n["latency_ms"] for n in g if n.get("latency_ms") is not None), default=None)
        res = sum(1 for n in g if n.get("kind") == "residential")
        html.append("<tr><td>%s %s</td><td>%d</td><td>%d</td><td>%s</td></tr>" % (
            flag_of(c), country_name(c), res, len(g) - res, ("%dms" % best) if best else "-"))
    html.append("</table><p>edgetunnel「自定义优选IP」填：<code>./public/nodes.txt</code> 的原始地址</p></body></html>")
    with open(os.path.join(OUT_DIR, "index.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(html))


def load_previous_count():
    p = os.path.join(OUT_DIR, "nodes.txt")
    if not os.path.isfile(p):
        return 0
    try:
        with open(p, encoding="utf-8") as f:
            return len([l for l in f if l.strip()])
    except Exception:
        return 0


def main():
    t_all = time.time()
    log("=" * 66)
    log("VPN Gate 住宅节点构建  %s" % datetime.now(TZ_CN).strftime("%Y-%m-%d %H:%M:%S"))
    log("=" * 66)

    rows, usable = fetch_rows()
    if not rows:
        log("!! 所有数据源都失败 —— 保留上一版结果，本次不做改动")
        return 0

    nodes = []
    seen = set()
    for n in to_sstp(rows):
        k = (n["ip"], n["port"])
        if k in seen:
            continue
        seen.add(k)
        nodes.append(n)
    log("SSTP 节点: %d" % len(nodes))
    if not nodes:
        log("!! 没有解析出 SSTP 节点 —— 保留上一版结果")
        return 0

    for n in nodes:
        n["kind"] = classify(n)
    res_n = sum(1 for n in nodes if n["kind"] == "residential")
    log("住宅 %d / 机房 %d / 未知 %d" % (
        res_n, sum(1 for n in nodes if n["kind"] == "datacenter"),
        sum(1 for n in nodes if n["kind"] == "unknown")))

    if KEEP_RESIDENTIAL_ONLY:
        nodes = [n for n in nodes if n["kind"] == "residential"]
        log("只保留住宅节点 -> %d" % len(nodes))

    log("-" * 66)
    log("开始验证（并发 %d，超时 %ds）：TCP 连通 + TLS 握手" % (CHECK_CONCURRENCY, CHECK_TIMEOUT))
    nodes = verify_all(nodes, log_fn=log)

    tls_ok = [n for n in nodes if n.get("verify") == "tls-ok"]
    tcp_ok = [n for n in nodes if n.get("alive")]
    log("TCP 可连: %d / %d    其中 TLS 握手成功: %d" % (len(tcp_ok), len(nodes), len(tls_ok)))

    keep = tls_ok
    if len(keep) < MIN_KEEP:
        log("!! TLS 成功数不足 %d，放宽为「TCP 可连」（仍剔除完全连不上的）" % MIN_KEEP)
        keep = tcp_ok
    if not keep:
        log("!! 没有任何节点通过验证 —— 保留上一版结果（不提交空文件）")
        return 0

    # 剔除太慢的（TLS 成功但延迟高，实际体验差）
    fast = [n for n in keep if n.get("latency_ms") is not None and n["latency_ms"] <= MAX_LATENCY_MS]
    if len(fast) >= MIN_KEEP:
        if len(fast) < len(keep):
            log("剔除延迟 > %dms 的节点：%d -> %d" % (MAX_LATENCY_MS, len(keep), len(fast)))
        keep = fast
    else:
        log("!! 低于 %dms 的节点不足 %d 个，保留全部（不做延迟剔除）" % (MAX_LATENCY_MS, MIN_KEEP))

    # 按延迟排序，取最快的 MAX_NODES 个
    keep.sort(key=lambda x: (x.get("latency_ms") is None, x.get("latency_ms") or 99999))
    if MAX_NODES and len(keep) > MAX_NODES:
        log("按延迟取最快的 %d 个（原有 %d 个）" % (MAX_NODES, len(keep)))
        keep = keep[:MAX_NODES]

    stats = {
        "total": len(keep),
        "residential": sum(1 for n in keep if n.get("kind") == "residential"),
        "verified_tls": len(tls_ok),
        "verified_tcp": len(tcp_ok),
        "sources": usable,
    }
    write_outputs(keep, stats)
    log("-" * 66)
    log("完成：输出 %d 个合格节点（住宅 %d），覆盖 %d 个国家，耗时 %.1fs" % (
        len(keep), stats["residential"], len(group_by_country(keep)), time.time() - t_all))
    for c, g in list(group_by_country(keep).items())[:15]:
        log("   %s %-10s %3d 个" % (flag_of(c), country_name(c), len(g)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        log("!! 出错: %s" % exc)
        import traceback
        traceback.print_exc()
        sys.exit(1)
