/**
 * MusicFree 音源插件 —— DJ 舞曲站合集
 * =====================================
 * 支持站点：
 *   1. 清风DJ   ddddj.com   搜索 ✓ 播放 ✓（直链 pan.urlkj.com）
 *   2. 呦呦DJ   djuu.com    搜索 ✓ 播放（自动探测多个媒体域名）
 *   3. 多多DJ   duoduodj.com 搜索 ✓（先取 cookie 再搜）
 *   4. 82dj     82dj.com    榜单浏览 ✓
 *   5. 西西DJ   dj.net      榜单浏览 ✓（GBK 站，仅支持站内榜单）
 *
 * 说明：
 *   · 插件运行环境（MusicFree）内置 axios / cheerio 等模块，可直接 require
 *   · 只解析站点**公开免费试听**的音频，不做任何付费/会员绕过
 *   · 该文件同时适用于 安卓版 MusicFree 与 Windows 版 MusicFree Desktop
 */

const axios = require("axios");
const cheerio = require("cheerio");

const UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

const HEADERS = {
  "User-Agent": UA,
  "Accept-Language": "zh-CN,zh;q=0.9",
};

/** 统一的 http 客户端（直连：这些站会屏蔽境外 IP，插件在手机上本来就是直连） */
const http = axios.create({
  timeout: 20000,
  headers: HEADERS,
  // 手机/桌面端都是本地网络直连，这里不设置代理
});

/** GBK 解码（该站是 GBK；TextDecoder 不支持时退化为 UTF-8） */
function decodeGbk(buf) {
  try {
    if (typeof buf === "string") return buf;
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer || buf);
    if (typeof TextDecoder !== "undefined") {
      try { return new TextDecoder("gbk").decode(bytes); } catch (e) { return new TextDecoder("utf-8").decode(bytes); }
    }
    return String.fromCharCode.apply(null, Array.prototype.slice.call(bytes));
  } catch (e) {
    return "";
  }
}

/* ------------------------------------------------------------------ */
/* 站点定义                                                            */
/* ------------------------------------------------------------------ */
const SITES = {
  ddddj: {
    name: "清风DJ",
    base: "https://www.ddddj.com",
    async search(query, page) {
      const url = `${this.base}/search.html?keys=${encodeURIComponent(query)}&page=${page}`;
      const { data: html } = await http.get(url, {
        headers: { ...HEADERS, Referer: this.base + "/" },
        responseType: "text",
        transformResponse: [(d) => d],
      });
      const $ = cheerio.load(html);
      const list = [];
      $('a[href^="/play/"]').each((_, el) => {
        const href = $(el).attr("href") || "";
        const title = ($(el).attr("title") || $(el).text() || "").trim();
        const m = href.match(/\/play\/(\d+)\.html/);
        if (!m || !title || title.length < 4) return;
        if (list.some((x) => x.songId === m[1])) return;
        list.push({
          songId: m[1],
          title,
          artist: title.split("-")[0].trim() || "DJ",
        });
      });
      return { list, isEnd: list.length === 0 };
    },
    async media(songId) {
      const { data: html } = await http.get(`${this.base}/play/${songId}.html`, {
        headers: { ...HEADERS, Referer: `${this.base}/play/${songId}.html` },
        responseType: "text",
        transformResponse: [(d) => d],
      });
      const m = html.match(/https?:\/\/[^\s"'<>]+\.(?:mp3|m4a|m3u8)[^\s"'<>]*/i);
      return m ? m[0].replace(/&amp;/g, "&") : null;
    },
  },

  djuu: {
    name: "呦呦DJ",
    base: "https://www.djuu.com",
    async search(query, page) {
      const url = `${this.base}/search?musicname=${encodeURIComponent(query)}&cid=0&list=2&page=${page}`;
      const { data: html } = await http.get(url, {
        headers: { ...HEADERS, Referer: this.base + "/" },
        responseType: "text",
        transformResponse: [(d) => d],
      });
      const $ = cheerio.load(html);
      const list = [];
      $("table.list_musiclist tr").each((_, tr) => {
        const a = $(tr).find('a[href^="/play/"]').first();
        const href = a.attr("href") || "";
        const m = href.match(/\/play\/(\d+)\.html/);
        if (!m) return;
        const title = (a.attr("title") || a.text() || "").trim();
        if (!title) return;
        const img = $(tr).find("img").attr("src") || "";
        const timeTxt = $(tr).find(".sc_2").first().text();
        list.push({
          songId: m[1],
          title,
          artist: title.split("-")[0].trim() || "DJ",
          artwork: img,
          durationText: timeTxt,
        });
      });
      return { list, isEnd: list.length === 0 };
    },
    async media(songId) {
      const { data: html } = await http.get(`${this.base}/play/${songId}.html`, {
        headers: { ...HEADERS, Referer: `${this.base}/play/${songId}.html` },
        responseType: "text",
        transformResponse: [(d) => d],
      });
      // 页面里有 var music = {..., file: 'c4/22/2026/xxxx', ...}
      const fm = html.match(/file\s*:\s*['"]([^'"]+)['"]/);
      const direct = html.match(/https?:\/\/[^\s"'<>]+\.(?:mp3|m4a|m3u8)[^\s"'<>]*/i);
      if (direct) return direct[0].replace(/&amp;/g, "&");
      if (!fm) return null;
      const file = fm[1];
      // 站点把音频按 file 片段拼在不同媒体域名下，逐个探测
      const hosts = ["https://down.djuu.com", "https://mp3.djuu.com", "https://mp.djuu.com", "https://music.djuu.com", "https://file.djuu.com"];
      const exts = [".mp3", ".m4a"];
      for (const h of hosts) {
        for (const e of exts) {
          const u = `${h}/${file}${e}`;
          try {
            const r = await http.head(u, { headers: { ...HEADERS, Referer: `${this.base}/play/${songId}.html` }, validateStatus: () => true });
            if (r.status === 200) return u;
          } catch (e) {
            /* 换下一个 */
          }
        }
      }
      return null;
    },
  },

  duoduodj: {
    name: "多多DJ",
    base: "http://www.duoduodj.com",
    async search(query, page) {
      // 首次访问会 Set-Cookie(ok / ASPSESSIONID) 并跳转 -> 请求两次并转发 cookie
      const url = `${this.base}/so.asp?k=${encodeURIComponent(query)}`;
      const opt = {
        headers: { ...HEADERS, Referer: this.base + "/" },
        responseType: "text",
        transformResponse: [(d) => d],
        validateStatus: () => true,
      };
      const r1 = await http.get(url, opt);
      const sc = r1.headers["set-cookie"];
      const cookie = Array.isArray(sc)
        ? sc.map((c) => String(c).split(";")[0]).join("; ")
        : sc
        ? String(sc).split(";")[0]
        : "ok=1";
      const r2 = await http.get(url, { ...opt, headers: { ...opt.headers, Cookie: cookie } });
      const $ = cheerio.load(r2.data);
      const list = [];
      $('a[href*="/dj/"]').each((_, el) => {
        const href = $(el).attr("href") || "";
        const m = href.match(/\/dj\/([^\/]+)\.html/);
        if (!m) return;
        const title = ($(el).attr("title") || $(el).text() || "").trim();
        if (!title || title.length < 4) return;
        if (list.some((x) => x.songId === m[1])) return;
        list.push({ songId: m[1], title, artist: title.split("-")[0].trim() || "DJ" });
      });
      return { list, isEnd: list.length === 0 };
    },
    async media(songId) {
      // 详情页里有 var KqDjurl="/djurlplays/xxxx.mp3"
      const page = `${this.base}/dj/${songId}.html`;
      const r = await http.get(page, {
        headers: { ...HEADERS, Referer: this.base + "/", Cookie: "ok=1" },
        responseType: "text",
        transformResponse: [(d) => d],
        validateStatus: () => true,
      });
      const m = String(r.data).match(/KqDjurl\s*=\s*["']([^"']+)["']/);
      if (!m) return null;
      const p = m[1];
      return p.startsWith("http") ? p : this.base + (p.startsWith("/") ? p : "/" + p);
    },
  },

  dj82: {
    name: "82DJ",
    base: "https://www.82dj.com",
    async search(query, page) {
      // 注：本站搜索结果是 JS 动态渲染，页面里没有可用的公开搜索 ajax 接口
      //     （站点提供的是 /index/index/del_search 这类历史记录接口，不是搜索）
      //     因此这里用首页最新列表兜底：至少能浏览最新发布的舞曲
      if (page > 1) return { list: [], isEnd: true };
      const { data: html } = await http.get(`${this.base}/`, {
        headers: { ...HEADERS, Referer: this.base + "/" },
        responseType: "text",
        transformResponse: [(d) => d],
      });
      const $ = cheerio.load(html);
      const list = [];
      $('a[href*="/play/"]').each((_, el) => {
        const href = $(el).attr("href") || "";
        const title = ($(el).attr("title") || $(el).text() || "").trim();
        const m = href.match(/\/play\/(\d+)/);
        if (!m || !title || title.length < 6) return;
        if (list.some((x) => x.songId === m[1])) return;
        list.push({ songId: m[1], title, artist: title.split("-")[0].trim() || "DJ" });
      });
      return { list: list.slice(0, 30), isEnd: true };
    },
    async media(songId) {
      const hdr = {
        ...HEADERS,
        Referer: `${this.base}/play/${songId}`,
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
      };
      // 站点的播放详情来自 /index/index/ajax_details（需要 type 参数，逐个试）
      for (const type of [1, 2, 0, 3, 4, 5, 6]) {
        try {
          const r = await http.post(`${this.base}/index/index/ajax_details`, `id=${songId}&type=${type}`, {
            headers: hdr,
            validateStatus: () => true,
            transformResponse: [(d) => d],
          });
          const txt = typeof r.data === "string" ? r.data : JSON.stringify(r.data);
          const mm = txt.match(/https?:\/\/[^\s"'<>]+\.(?:mp3|m4a|m3u8)[^\s"'<>]*/i);
          if (mm) return mm[0].replace(/&amp;/g, "&");
        } catch (e) {
          /* 试下一个 type */
        }
      }
      // 兜底：详情页里直接找
      const { data: html } = await http.get(`${this.base}/play/${songId}`, {
        headers: { ...HEADERS, Referer: `${this.base}/play/${songId}` },
        responseType: "text",
        transformResponse: [(d) => d],
      });
      const m = String(html).match(/https?:\/\/[^\s"'<>]+\.(?:mp3|m4a|m3u8)[^\s"'<>]*/i);
      return m ? m[0].replace(/&amp;/g, "&") : null;
    },
  },
  djnet: {
    name: "西西DJ",
    base: "https://www.dj.net",
    async search(query, page) {
      // 该站是 GBK + Discuz：搜索受编码限制，这里用站内音乐搜索（ASCII 关键词最稳）
      const url = `${this.base}/search.php?mod=music&srchtxt=${encodeURIComponent(query)}&searchsubmit=yes`;
      const r = await http.get(url, {
        headers: { ...HEADERS, Referer: this.base + "/" },
        responseType: "arraybuffer",
        validateStatus: () => true,
      });
      const html = decodeGbk(r.data);
      const $ = cheerio.load(html);
      const list = [];
      $('a[href*="/djplay/music"]').each((_, el) => {
        const href = $(el).attr("href") || "";
        const m = href.match(/music(\d+)\.html/);
        const title = ($(el).text() || "").trim();
        if (!m || !title || title.length < 3) return;
        if (list.some((x) => x.songId === m[1])) return;
        list.push({ songId: m[1], title, artist: title.split("-")[0].trim() || "DJ" });
      });
      return { list, isEnd: list.length === 0 };
    },
    async media(songId) {
      const page = `${this.base}/djplay/music${songId}.html`;
      const r = await http.get(page, {
        headers: { ...HEADERS, Referer: this.base + "/" },
        responseType: "arraybuffer",
        validateStatus: () => true,
      });
      const html = decodeGbk(r.data);
      const m = html.match(/https?:\/\/[^\s"'<>]+\.(?:mp3|m4a|m3u8)[^\s"'<>]*/i);
      if (!m) {
        // 实测结论：西西DJ 播放页不直接给音频地址（走站内播放条 JS 动态取），
        // 因此这里明确报错，避免返回一个播不了的地址。
        throw new Error("西西DJ：该曲目音频由站内播放器动态获取，插件暂无法直链播放");
      }
      return m[0].replace(/&amp;/g, "&");
    },
  },
};

const SITE_ORDER = ["ddddj", "duoduodj", "djuu", "dj82", "djnet"];

/* ------------------------------------------------------------------ */
/* MusicFree 插件接口                                                  */
/* ------------------------------------------------------------------ */
module.exports = {
  platform: "DJ舞曲合集",
  version: "0.6.1",
  author: "zhuli",
  srcUrl: "",
  cacheControl: "no-cache",
  primaryKey: ["id"],

  /** 搜索：并发查所有站点，合并结果 */
  async search(query, page, type) {
    if (type && type !== "music") {
      return { isEnd: true, data: [] };
    }
    const tasks = SITE_ORDER.map(async (key) => {
      const site = SITES[key];
      try {
        const r = await site.search(query, page);
        return (r.list || []).map((it) => ({
          id: `${key}:${it.songId}${it.href ? "|" + it.href : ""}`,
          title: `[${site.name}] ${it.title}`,
          artist: it.artist || "DJ",
          album: site.name,
          artwork: it.artwork || undefined,
          duration: undefined,
          _site: key,
          _songId: it.songId,
          _href: it.href || "",
        }));
      } catch (e) {
        return [];
      }
    });
    const groups = await Promise.all(tasks);
    const data = [].concat(...groups);
    return { isEnd: !data.length, data };
  },

  /** 解析播放地址 */
  async getMediaSource(musicItem, quality) {
    const id = String(musicItem.id || "");
    const key = id.split(":")[0];
    const rest = id.slice(key.length + 1);
    const [songId, href] = rest.split("|");
    const site = SITES[key];
    if (!site) throw new Error("未知站点: " + key);
    const url = await site.media(songId, { href: href || "" });
    if (!url) throw new Error(`${site.name} 没有取到播放地址（可能是会员曲目或站点改版）`);
    return {
      url,
      headers: { ...HEADERS, Referer: site.base + "/" },
    };
  },

  /** 歌词：DJ 站本身没有歌词接口，这里用网易云做兜底（查不到就返回空，不报错） */
  async getLyric(musicItem) {
    try {
      const raw = `${musicItem.artist || ""} ${musicItem.title || ""}`
        .replace(/^\[[^\]]+\]\s*/, "")
        .replace(/\(.*?Rmx.*?\)|\(.*?Remix.*?\)/gi, " ")
        .replace(/[-—|]/g, " ")
        .trim();
      const q = encodeURIComponent(raw);
      const s = await http.get(`https://music.163.com/api/search/get/web?s=${q}&type=1&limit=1`, {
        headers: { ...HEADERS, Referer: "https://music.163.com/" },
        validateStatus: () => true,
      });
      const d = typeof s.data === "string" ? JSON.parse(s.data) : s.data;
      const song = d && d.result && d.result.songs && d.result.songs[0];
      if (!song) return { rawLrc: "" };
      const l = await http.get(`https://music.163.com/api/song/lyric?id=${song.id}&lv=1&kv=1&tv=-1`, {
        headers: { ...HEADERS, Referer: "https://music.163.com/" },
        validateStatus: () => true,
      });
      const ld = typeof l.data === "string" ? JSON.parse(l.data) : l.data;
      return { rawLrc: (ld && ld.lrc && ld.lrc.lyric) || "" };
    } catch (e) {
      return { rawLrc: "" };
    }
  },

  /** 榜单/分类入口（MusicFree 侧边栏） */
  async getTopLists() {
    return [
      {
        title: "站点最新",
        data: SITE_ORDER.map((k) => ({
          id: k,
          title: SITES[k].name + " · 最新",
          description: SITES[k].base,
          coverImg: "",
        })),
      },
    ];
  },

  async getTopListDetail(topListItem, page) {
    const site = SITES[topListItem.id];
    if (!site) return { isEnd: true, musicList: [] };
    // 借搜索接口拉最新（关键词用空/热门字）
    const r = await site.search("DJ", page || 1);
    return {
      isEnd: !(r.list || []).length,
      musicList: (r.list || []).map((it) => ({
        id: `${topListItem.id}:${it.songId}${it.href ? "|" + it.href : ""}`,
        title: `[${site.name}] ${it.title}`,
        artist: it.artist || "DJ",
        album: site.name,
        artwork: it.artwork || undefined,
      })),
    };
  },
};
