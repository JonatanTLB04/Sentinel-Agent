"use strict";
// safe-fetch.js - the only way the investigator is allowed to "open a web page".
//  * public internet only: every resolved IP is checked, private/loopback/link-local/
//    cloud-metadata ranges are refused, and we CONNECT TO THE CHECKED IP (no DNS rebinding)
//  * GET only, no cookies, no credentials, no JavaScript execution (we only read bytes)
//  * hard limits on redirects, size and time
//  * returns plain text, never raw HTML

const dns = require("dns").promises;
const net = require("net");
const http = require("http");
const https = require("https");
const { redactString } = require("./redact");

const ALLOWED_PORTS = new Set([80, 443, 8080, 8443]);
const TEXT_TYPES = /^(text\/|application\/(json|xml|xhtml\+xml|rdap\+json)|application\/.*\+json)/i;

// ---------- IP classification ----------
function ipv4ToInt(ip) {
  const p = ip.split(".").map(Number);
  return ((p[0] << 24) >>> 0) + (p[1] << 16) + (p[2] << 8) + p[3];
}

const V4_BLOCKS = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

function isPrivateV4(ip) {
  const n = ipv4ToInt(ip);
  return V4_BLOCKS.some(([base, bits]) => {
    const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
    return (n & mask) >>> 0 === (ipv4ToInt(base) & mask) >>> 0;
  });
}

function expandV6(ip) {
  let s = ip.toLowerCase().split("%")[0];
  let tailV4 = null;
  const m = s.match(/^(.*:)(\d+\.\d+\.\d+\.\d+)$/);
  if (m) {
    tailV4 = m[2];
    const p = tailV4.split(".").map(Number);
    s = m[1] + ((p[0] << 8) | p[1]).toString(16) + ":" + ((p[2] << 8) | p[3]).toString(16);
  }
  const halves = s.split("::");
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length > 1 && halves[1] ? halves[1].split(":") : [];
  const fill = 8 - head.length - tail.length;
  const groups = halves.length > 1 ? [...head, ...Array(Math.max(fill, 0)).fill("0"), ...tail] : head;
  const bytes = [];
  for (const g of groups) {
    const v = parseInt(g || "0", 16);
    bytes.push((v >> 8) & 255, v & 255);
  }
  return bytes;
}

function isPrivateV6(ip) {
  const b = expandV6(ip);
  if (b.length !== 16) return true; // unparseable -> refuse
  const allZero = b.every((x) => x === 0);
  if (allZero) return true; // ::
  if (b.slice(0, 15).every((x) => x === 0) && b[15] === 1) return true; // ::1
  if ((b[0] & 0xfe) === 0xfc) return true; // fc00::/7 unique local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if (b[0] === 0xff) return true; // multicast
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true; // doc
  if (b[0] === 0x20 && b[1] === 0x02) return true; // 6to4
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x00 && b[3] === 0x00) return true; // teredo
  if (b[0] === 0x01 && b[1] === 0x00 && b.slice(2, 8).every((x) => x === 0)) return true; // 100::/64
  // IPv4-mapped (::ffff:a.b.c.d) and NAT64 (64:ff9b::/96): judge the embedded IPv4
  const mapped = b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff;
  const nat64 = b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b && b.slice(4, 12).every((x) => x === 0);
  if (mapped || nat64) return isPrivateV4(`${b[12]}.${b[13]}.${b[14]}.${b[15]}`);
  return false;
}

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateV4(ip);
  if (net.isIPv6(ip)) return isPrivateV6(ip);
  return true;
}

function badHostname(host) {
  const h = host.toLowerCase().replace(/\.$/, "");
  if (!h) return true;
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan") || h.endsWith(".corp") || h.endsWith(".home")) return true;
  if (!net.isIP(h) && !h.includes(".")) return true; // single-label (intranet) names
  return false;
}

async function resolvePublicAddress(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "");
  if (badHostname(host)) throw new Error(`host not allowed: ${host}`);
  if (net.isIP(host)) {
    if (isPrivateIp(host)) throw new Error(`private/reserved address refused: ${host}`);
    return host;
  }
  const addrs = await dns.lookup(host, { all: true });
  if (!addrs.length) throw new Error(`could not resolve ${host}`);
  for (const a of addrs) {
    if (isPrivateIp(a.address)) throw new Error(`${host} resolves to a private/reserved address; refused`);
  }
  const v4 = addrs.find((a) => a.family === 4);
  return (v4 || addrs[0]).address;
}

// ---------- one HTTP request against an already-validated IP ----------
function requestOnce(url, ip, { timeoutMs = 8000, maxBytes = 200000 } = {}) {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const lib = isHttps ? https : http;
    const port = url.port ? Number(url.port) : isHttps ? 443 : 80;
    const options = {
      host: ip,
      port,
      path: url.pathname + url.search,
      method: "GET",
      agent: false,
      headers: {
        Host: url.host,
        "User-Agent": "SENTINEL-Investigator/1.0 (security triage; read-only)",
        Accept: "text/html,text/plain,application/json;q=0.9,*/*;q=0.1",
        "Accept-Encoding": "identity",
      },
    };
    if (isHttps) options.servername = url.hostname; // SNI + certificate check against the real name
    const req = lib.request(options, (res) => {
      const status = res.statusCode || 0;
      const contentType = String(res.headers["content-type"] || "");
      const location = res.headers.location || null;
      const chunks = [];
      let size = 0;
      let truncated = false;
      if (!TEXT_TYPES.test(contentType) && !(status >= 300 && status < 400)) {
        res.destroy();
        return resolve({ status, contentType, location, body: Buffer.alloc(0), truncated: false, skippedBody: true });
      }
      res.on("data", (c) => {
        size += c.length;
        if (size > maxBytes) {
          truncated = true;
          chunks.push(c.slice(0, c.length - (size - maxBytes)));
          res.destroy();
          return;
        }
        chunks.push(c);
      });
      const finish = () => resolve({ status, contentType, location, body: Buffer.concat(chunks), truncated });
      res.on("end", finish);
      res.on("close", finish);
      res.on("error", () => finish());
    });
    req.setTimeout(timeoutMs, () => req.destroy(new Error("timeout")));
    req.on("error", reject);
    req.end();
  });
}

// ---------- HTML -> text ----------
function decodeEntities(s) {
  return s
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;|&apos;/gi, "'");
}

function htmlToText(html) {
  const title = ((html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "").trim();
  const description = ((html.match(/<meta[^>]+name=["']description["'][^>]*content=["']([^"']*)["']/i) || [])[1] || "").trim();
  let t = html
    .replace(/<(script|style|noscript|svg|template|iframe)[\s\S]*?<\/\1>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/<[^>]+>/g, " ");
  t = decodeEntities(t).replace(/\s+/g, " ").trim();
  return { title: decodeEntities(title), description: decodeEntities(description), text: t };
}

// ---------- public API ----------
async function safeGet(urlStr, opts = {}) {
  const maxRedirects = opts.maxRedirects ?? 3;
  let current;
  try {
    current = new URL(urlStr);
  } catch (_) {
    throw new Error("invalid URL");
  }
  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (!["http:", "https:"].includes(current.protocol)) throw new Error("only http/https URLs are allowed");
    if (current.username || current.password) throw new Error("URLs with credentials are not allowed");
    const port = current.port ? Number(current.port) : current.protocol === "https:" ? 443 : 80;
    if (!ALLOWED_PORTS.has(port)) throw new Error(`port ${port} not allowed`);
    const ip = await resolvePublicAddress(current.hostname);
    const res = await requestOnce(current, ip, opts);
    if ([301, 302, 303, 307, 308].includes(res.status) && res.location) {
      current = new URL(res.location, current);
      continue;
    }
    return { finalUrl: current.toString(), ...res };
  }
  throw new Error("too many redirects");
}

// What the investigator sees: a short, redacted, plain-text summary.
async function fetchPageSummary(urlStr, opts = {}) {
  const res = await safeGet(urlStr, opts);
  const out = {
    finalUrl: redactString(res.finalUrl),
    status: res.status,
    contentType: res.contentType,
    truncated: !!res.truncated,
  };
  if (res.skippedBody) {
    out.note = "Non-text content; body not read.";
    return out;
  }
  const raw = res.body.toString("utf8");
  if (/html/i.test(res.contentType)) {
    const { title, description, text } = htmlToText(raw);
    out.title = redactString(title).slice(0, 200);
    out.description = redactString(description).slice(0, 400);
    out.text = redactString(text).slice(0, opts.maxText || 3000);
  } else {
    out.text = redactString(raw.replace(/\s+/g, " ").trim()).slice(0, opts.maxText || 3000);
  }
  return out;
}

module.exports = {
  isPrivateIp,
  resolvePublicAddress,
  safeGet,
  fetchPageSummary,
  htmlToText,
  _requestOnce: requestOnce,
};
