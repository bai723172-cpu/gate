#!/usr/bin/env python3
"""
VPN Gate SSTP 节点检测流水线（低风险完整版）
=============================================
功能：
  1. 自动发现官方镜像 + 多静态源抓取节点
  2. 只保留带 TCP 入口的 SSTP 节点并去重
  3. 并发调用检测 Worker（带数量/并发限制）
  4. 默认只输出住宅节点
  5. 生成 public/data.json + public/index.html + public/nodes.txt
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
from urllib.parse import quote

import requests

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# ---------------------------------------------------------------------------
# 低风险配置
# ---------------------------------------------------------------------------
REPO_DIR = os.path.dirname(os.path.abspath(__file__))

# 静态数据源（可环境变量覆盖）
VPNGATE_SOURCES = [
    os.environ.get("VPNGATE_API", "http://www.vpngate.net/api/iphone/"),
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv",
    "https://cdn.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/servers.json",
    "https://fastly.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/vpngate.csv",
    "https://gcore.jsdelivr.net/gh/GeorgeXie2333/vpngate-list-mirror@latest/data/servers.json",
    "https://raw.githubusercontent.com/fdciabdul/Vpngate-Scraper-API/main/json/data.json",
    "https://raw.githubusercontent.com/sinspired/VpngateAPI/main/servers.csv",
]

_extra = os.environ.get("VPNGATE_EXTRA_SOURCES", "").strip()
if _extra:
    VPNGATE_SOURCES.extend([u.strip() for u in _extra.split(",") if u.strip()])

# 检测 Worker（强烈建议加 token）
WORKER_CHECK_URL = os.environ.get(
    "CHECK_WORKER",
    "https://你的域名/check?token=你的随机长字符串&sstp=vpn:vpn@"
)

# 低风险参数
CONCURRENCY = max(1, int(os.environ.get("CHECK_CONCURRENCY", "8")))
CHECK_TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "45"))
MAX_CHECK_NODES = int(os.environ.get("MAX_CHECK_NODES", "120"))
HTTP_TIMEOUT = int(os.environ.get("HTTP_TIMEOUT", "30"))

# 默认只输出住宅节点
ONLY_RESIDENTIAL = os.environ.get("ONLY_RESIDENTIAL", "true").lower() in ("1", "true", "yes", "on")

# 缓存
CACHE_DIR = os.path.join(REPO_DIR, ".cache")
CACHE_FILE = os.path.join(CACHE_DIR, "vpngate_last_success.json")
CACHE_MAX_AGE_HOURS = int(os.environ.get("CACHE_MAX_AGE_HOURS", "8"))

PUBLIC_DIR = os.environ.get("PUBLIC_DIR", os.path.join(REPO_DIR, "public"))
TEMPLATE_HTML = os.path.join(REPO_DIR, "web", "index.html")
NODES_URL = os.environ.get("NODES_URL", "https://bai723172-cpu.github.io/gate/nodes.txt")

# 静态优选域名池
EDGE_HOSTS = [
    h.strip()
    for h in os.environ.get(
        "EDGE_HOSTS",
        "",
    ).split(",")
    if h.strip()
]

OPTIMAL_API = os.environ.get("OPTIMAL_API", "https://cf.090227.xyz/ct?ips=6&port=443,https://cf.090227.xyz/cu?port=443,https://cf.090227.xyz/cmcc?ips=8&port=443")

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
# 自动发现官方镜像
# ---------------------------------------------------------------------------
def discover_vpngate_mirrors(session=None, timeout=12):
    if session is None:
        session = requests.Session()

    mirror_list_urls = [
        "https://www.vpngate.net/en/sites.aspx",
        "http://www.vpngate.net/en/sites.aspx",
        "https://www.vpngate.net/cn/sites.aspx",
        "http://www.vpngate.net/cn/sites.aspx",
    ]

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    mirrors = []
    for list_url in mirror_list_urls:
        try:
            log("VPN GATE", f"正在抓取镜像列表: {list_url}")
            resp = session.get(list_url, headers=headers, timeout=timeout)
            if resp.status_code != 200:
                continue

            pattern = re.compile(r'https?://[0-9a-zA-Z\.\-:]+(?=/|\s|"|\'|<)', re.IGNORECASE)
            found = pattern.findall(resp.text)

            for m in found:
                m = m.rstrip("/")
                if "vpngate.net" in m.lower():
                    continue
                if m not in mirrors and ("." in m or ":" in m):
                    mirrors.append(m)

            if mirrors:
                log("VPN GATE", f"从官方列表发现 {len(mirrors)} 个镜像站点")
                break
        except Exception as e:
            log("VPN GATE", f"抓取镜像列表失败 ({list_url}): {e}")

    api_urls = []
    for base in mirrors:
        api_urls.append(f"{base}/api/iphone/")
        if not base.endswith(("/en", "/cn")):
            api_urls.append(f"{base}/en/api/iphone/")
            api_urls.append(f"{base}/cn/api/iphone/")

    seen = set()
    unique = []
    for u in api_urls:
        if u not in seen:
            seen.add(u)
            unique.append(u)
    return unique

# ---------------------------------------------------------------------------
# 数据抓取
# ---------------------------------------------------------------------------
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
        if len(fields) < 7:
            continue
        host = fields[pos["hostname"]].strip()
        ip = fields[pos["ip"]].strip()
        if not host or not ip:
            continue
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
        elif isinstance(item, dict) and isinstance(item.get("data"), list):
            servers.extend(item["data"])
        elif isinstance(item, dict):
            servers.append(item)
    rows = []
    for s in servers:
        host = str(s.get("hostname") or s.get("host") or s.get("HostName") or "").strip()
        ip = str(s.get("ip") or s.get("IP") or "").strip()
        if not host or not ip:
            continue
        rows.append({
            "host": host,
            "ip": ip,
            "country_long": str(s.get("countrylong") or s.get("country_long") or s.get("CountryLong") or s.get("country") or "").strip(),
            "country_short": str(s.get("countryshort") or s.get("country_short") or s.get("CountryShort") or "").strip(),
            "config_b64": str(s.get("openvpn_configdata_base64") or s.get("config_b64") or s.get("OpenVPN_ConfigData_Base64") or s.get("ovpn") or "").strip(),
        })
    return rows

def fetch_vpngate():
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
        "Accept": "text/csv,application/json,text/plain,*/*",
    }
    session = requests.Session()

    # 自动发现动态镜像
    try:
        dynamic = discover_vpngate_mirrors(session=session)
        log("VPN GATE", f"自动发现动态镜像 API 数量: {len(dynamic)}")
    except Exception as e:
        log("VPN GATE", f"自动发现失败: {e}")
        dynamic = []

    all_sources = dynamic + VPNGATE_SOURCES
    seen = set()
    sources = []
    for s in all_sources:
        if s and s not in seen:
            seen.add(s)
            sources.append(s)

    for idx, url in enumerate(sources, 1):
        try:
            log("VPN GATE", f"[{idx}/{len(sources)}] 尝试: {url}")
            resp = session.get(url, timeout=HTTP_TIMEOUT, headers=headers)
            resp.raise_for_status()
            content_type = resp.headers.get("Content-Type", "").lower()
            text = resp.text

            if "json" in content_type or url.rstrip("/").endswith((".json", "data.json", "servers.json")):
                rows = parse_mirror_json(resp.json())
            else:
                rows = parse_csv(text)

            if rows and len(rows) > 10:
                log("VPN GATE", f"成功获取 {len(rows)} 个原始节点 ← {url}")
                try:
                    os.makedirs(CACHE_DIR, exist_ok=True)
                    with open(CACHE_FILE, "w", encoding="utf-8") as f:
                        json.dump({
                            "fetched_at": datetime.now(timezone.utc).isoformat(),
                            "source": url,
                            "rows": rows,
                        }, f, ensure_ascii=False)
                except Exception as e:
                    log("VPN GATE", f"缓存写入失败: {e}")
                return rows, url
            else:
                log("VPN GATE", f"数据过少，跳过")
        except Exception as exc:
            log("VPN GATE", f"失败: {type(exc).__name__}: {exc}")

    # 缓存兜底
    log("VPN GATE", "所有在线源失败，尝试本地缓存...")
    try:
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                cache = json.load(f)
            fetched_at = datetime.fromisoformat(cache["fetched_at"].replace("Z", "+00:00"))
            age_hours = (datetime.now(timezone.utc) - fetched_at).total_seconds() / 3600
            if age_hours <= CACHE_MAX_AGE_HOURS:
                rows = cache["rows"]
                log("VPN GATE", f"使用缓存（{age_hours:.1f}小时前），共 {len(rows)} 个节点")
                return rows, f"cache:{cache.get('source', 'unknown')}"
    except Exception as e:
        log("VPN GATE", f"读取缓存失败: {e}")

    die("VPN Gate 所有数据源（含缓存）均不可用")

# ---------------------------------------------------------------------------
# 优选 API
# ---------------------------------------------------------------------------
def fetch_optimal_api_endpoints(api_urls_str):
    if not api_urls_str.strip():
        return []
    endpoints = []
    urls = [u.strip() for u in api_urls_str.split(",") if u.strip()]
    for url in urls:
        try:
            log("OPTIMAL API", f"请求优选 API: {url}")
            resp = requests.get(url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                lines = resp.text.strip().splitlines()
                count = 0
                for line in lines:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    endpoint = line.split("#")[0].strip()
                    if endpoint:
                        if ":" not in endpoint:
                            endpoint = f"{endpoint}:443"
                        endpoints.append(endpoint)
                        count += 1
                log("OPTIMAL API", f"成功获取 {count} 个优选端点")
        except Exception as e:
            log("OPTIMAL API", f"拉取失败 ({url}): {e}")
    return endpoints

def get_combined_edge_hosts():
    _entry = os.environ.get("HOSTS_ENTRY", "").strip()
    static_hosts = [e.strip() for e in _entry.split(",") if e.strip()] if _entry else EDGE_HOSTS
    api_hosts = fetch_optimal_api_endpoints(OPTIMAL_API)

    combined = []
    seen = set()
    for h in static_hosts + api_hosts:
        if h and h not in seen:
            seen.add(h)
            combined.append(h)

    log("EDGE POOL", f"汇总入口: 静态 {len(static_hosts)} + API {len(api_hosts)} = {len(combined)}")
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
        if not _PROTO_TCP_RE.search(cfg):
            continue
        m = _REMOTE_RE.search(cfg)
        if not m:
            continue
        port = int(m.group(1))
        if not (1 <= port <= 65535):
            continue
        host = r["host"]
        if not host.endswith(".opengw.net"):
            host = f"{host}.opengw.net"
        nodes.append({
            "host": host,
            "port": port,
            "ip": r["ip"],
            "country": r["country_long"],
            "country_code": r["country_short"],
        })
    return nodes

def dedupe(nodes):
    seen = set()
    out = []
    for n in nodes:
        key = (n["host"].lower(), n["port"], "sstp")
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    return out

# ---------------------------------------------------------------------------
# 检测 Worker
# ---------------------------------------------------------------------------
def classify_network(host, exit_org, is_datacenter=None):
    if is_datacenter is True:
        return "datacenter"
    if is_datacenter is False:
        return "residential"
    org = (exit_org or "").upper()
    if org:
        if any(k in org for k in DATA_CENTER_ORG_KEYWORDS):
            return "datacenter"
        if any(k in org for k in RESIDENTIAL_ORG_KEYWORDS):
            return "residential"
    h = host.lower()
    if h.startswith("public-vpn"):
        return "datacenter"
    if re.match(r"^vpn\d{5,}", h) or re.match(r"^vpnv\d+", h):
        return "residential"
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
    results = []
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        futures = [pool.submit(check_one, n, session) for n in nodes]
        for fut in as_completed(futures):
            results.append(fut.result())
    return results

# ---------------------------------------------------------------------------
# 生成数据
# ---------------------------------------------------------------------------
def build_outputs(results, raw_count, sstp_count, source):
    available = [r for r in results if r.get("success")]

    if ONLY_RESIDENTIAL:
        available = [r for r in available if r.get("residential") == "residential"]
        log("RESULT", f"仅保留住宅节点后剩余: {len(available)}")

    countries = {}
    for n in available:
        c = n["country"] or "未知"
        countries.setdefault(c, {"code": n["country_code"] or "?", "nodes": []})["nodes"].append(n)

    stats = {
        "raw_nodes": raw_count,
        "sstp_nodes": sstp_count,
        "checked": len(results),
        "success": len([r for r in results if r.get("success")]),
        "residential_kept": len(available),
        "failed": len(results) - len([r for r in results if r.get("success")]),
        "countries": len(countries),
        "residential_est": sum(1 for n in available if n["residential"] == "residential"),
        "datacenter_est": sum(1 for n in available if n["residential"] == "datacenter"),
        "only_residential": ONLY_RESIDENTIAL,
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
        "worker": WORKER_CHECK_URL.split("?")[0],
        "stats": stats,
        "countries": by_country,
        "available": available,
    }
    return data

def build_nodes_text(data, edge_hosts):
    countries = data["countries"]
    edge = edge_hosts
    lines = []
    idx = 0
    ordered = sorted(
        countries.items(),
        key=lambda kv: (-int(kv[1].get("count") or 0), str(kv[1].get("code") or kv[0]))
    )
    for cname, grp in ordered:
        code = str(grp.get("code") or "?").upper()
        zh = COUNTRY_ZH.get(code) or (code if code and code != "?" else cname)
        nodes = sorted(
            grp["nodes"],
            key=lambda n: (n.get("latency_ms") is None, n.get("latency_ms") or 0, n.get("host") or "")
        )
        for i, n in enumerate(nodes, 1):
            entry = edge[idx % len(edge)]
            idx += 1
            lines.append(f"{entry}#{zh}-住宅-{i:02d}$sstp://vpn:vpn@{n['host']}:{n['port']}")
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
            "<html><head><meta charset='utf-8'><title>VPN Gate SSTP 住宅节点</title></head>"
            "<body><h1>VPN Gate SSTP 住宅节点</h1><pre id='out'></pre></body>"
            "<script>fetch('data.json').then(r=>r.json()).then(d=>out.textContent=JSON.stringify(d.stats,null,2)).catch(e=>out.textContent='加载失败:'+e)</script></html>"
        )
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    nodes_path = os.path.join(PUBLIC_DIR, "nodes.txt")
    with open(nodes_path, "w", encoding="utf-8") as f:
        f.write(build_nodes_text(data, edge_hosts))

    return data_path, html_path, nodes_path

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def main():
    session = requests.Session()
    rows, source = fetch_vpngate()
    raw_count = len(rows)
    if raw_count == 0:
        die("VPN Gate 返回 0 个原始节点")

    sstp_nodes = to_sstp_nodes(rows)
    sstp_count = len(sstp_nodes)
    if sstp_count == 0:
        die(f"从 {raw_count} 个原始节点中没有解析出任何 SSTP(TCP) 节点")

    uniq = dedupe(sstp_nodes)

    if MAX_CHECK_NODES > 0:
        uniq = uniq[:MAX_CHECK_NODES]

    log("VPN GATE", f"获取原始节点: {raw_count}")
    log("VPN GATE", f"SSTP 节点: {sstp_count}")
    log("VPN GATE", f"去重后: {len(uniq)} (限制检测 {MAX_CHECK_NODES})")

    log("CLOUDFLARE WORKER", f"提交检测: {len(uniq)} (并发 {CONCURRENCY}, 超时 {CHECK_TIMEOUT}s)")
    t0 = time.time()
    results = check_all(uniq, session)
    elapsed = time.time() - t0

    success = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    worker_errors = [r for r in failed if r.get("worker_error")]

    log("CLOUDFLARE WORKER", f"检测成功: {len(success)}")
    log("CLOUDFLARE WORKER", f"检测失败: {len(failed)}" + (f" (Worker异常 {len(worker_errors)})" if worker_errors else ""))
    log("CLOUDFLARE WORKER", f"耗时: {elapsed:.1f}s")

    if uniq and not success and len(worker_errors) == len(uniq):
        die("Worker 全部请求异常，检测服务不可用")

    data = build_outputs(results, raw_count, sstp_count, source)
    log("RESULT", f"最终可用住宅节点: {data['stats']['residential_kept']}")
    log("RESULT", f"国家数量: {data['stats']['countries']}")

    edge_hosts = get_combined_edge_hosts()
    data_path, html_path, nodes_path = write_outputs(data, edge_hosts)

    log("WEBSITE", f"生成 {os.path.relpath(data_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(html_path, REPO_DIR)}")
    log("WEBSITE", f"生成 {os.path.relpath(nodes_path, REPO_DIR)}")
    log("USAGE", f"把 {NODES_URL} 填入 edgetunnel 后台「自定义优选IP」即可自动轮换")
    log("WEBSITE", "完成")

if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:
        die(f"程序异常: {type(exc).__name__}: {exc}")
