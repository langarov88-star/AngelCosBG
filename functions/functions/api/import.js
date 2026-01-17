export async function onRequestPost({ request, env }) {
  const authErr = await requireAuth(request, env);
  if (authErr) return authErr;

  let body;
  try { body = await request.json(); }
  catch { return json({ error: "Invalid JSON body" }, 400); }

  const urls = Array.isArray(body.urls) ? body.urls.slice(0, 10) : [];
  if (!urls.length) return json({ error: "Missing urls" }, 400);

  const items = [];
  for (const raw of urls) {
    const url = String(raw || "").trim();
    if (!url) continue;

    const v = validateUrlNoAllowlist(url);
    if (!v.ok) {
      items.push({ url, error: v.error });
      continue;
    }

    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 15000);

      const resp = await fetch(url, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "bg-BG,bg;q=0.9,en;q=0.8",
          "Cache-Control": "no-cache",
          "Pragma": "no-cache"
        }
      }).finally(() => clearTimeout(timeout));

      const ct = (resp.headers.get("content-type") || "").toLowerCase();
      if (!resp.ok) throw new Error(`Fetch failed (${resp.status})`);
      if (!ct.includes("text/html") && !ct.includes("text/plain")) {
        throw new Error(`Unsupported content-type: ${ct || "unknown"}`);
      }

      const html = await resp.text();
      const title = extractTitle(html);
      const text = htmlToText(html).slice(0, 6000);

      items.push({ url, title, text });

    } catch (e) {
      const msg = e?.name === "AbortError" ? "Timeout (15s)" : String(e?.message || e);
      items.push({ url, error: msg });
    }
  }

  return json({ items }, 200);
}

function validateUrlNoAllowlist(raw) {
  let u;
  try { u = new URL(raw); } catch { return { ok: false, error: "Invalid URL" }; }

  if (u.protocol !== "https:" && u.protocol !== "http:") {
    return { ok: false, error: "Only http/https allowed" };
  }

  const host = u.hostname.toLowerCase();

  // Block localhost / internal names
  if (host === "localhost" || host.endsWith(".local")) {
    return { ok: false, error: "Blocked host" };
  }

  // Block IP-literals in private ranges
  if (isIpLiteral(host) && isPrivateIp(host)) {
    return { ok: false, error: "Blocked private IP" };
  }

  return { ok: true };
}

function isIpLiteral(host) {
  // IPv4 only (достатъчно за практиката тук)
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}

function isPrivateIp(ip) {
  const p = ip.split(".").map(n => Number(n));
  if (p.length !== 4 || p.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true;

  // 10.0.0.0/8
  if (p[0] === 10) return true;
  // 127.0.0.0/8
  if (p[0] === 127) return true;
  // 169.254.0.0/16
  if (p[0] === 169 && p[1] === 254) return true;
  // 172.16.0.0/12
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  // 192.168.0.0/16
  if (p[0] === 192 && p[1] === 168) return true;
  // 0.0.0.0/8
  if (p[0] === 0) return true;

  return false;
}

function extractTitle(html) {
  const m = html.match(/<title[^>]*>([\s\S]*?)<\/title>/i);
  if (!m) return "";
  return decodeHtml(m[1]).replace(/\s+/g, " ").trim().slice(0, 180);
}

function htmlToText(html) {
  let s = html
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript[\s\S]*?<\/noscript>/gi, " ");

  s = s
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/(p|div|li|h1|h2|h3|h4|tr|section|article)>/gi, "\n");

  s = s.replace(/<[^>]+>/g, " ");
  s = decodeHtml(s);
  s = s.replace(/\r/g, "").replace(/[ \t]+/g, " ").replace(/\n{3,}/g, "\n\n").trim();
  return s;
}

function decodeHtml(str) {
  return String(str || "")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&#039;/g, "'")
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(Number(n)));
}

/* ---------------- AUTH (same pattern) ---------------- */

async function requireAuth(request, env) {
  if (!env?.ACCESS_TOKEN_SECRET) return json({ error: "ACCESS_TOKEN_SECRET missing in env" }, 500);

  const auth = request.headers.get("authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
  if (!token || !token.includes(".")) return json({ error: "Unauthorized" }, 401);

  const [payloadB64, sigB64] = token.split(".");
  if (!payloadB64 || !sigB64) return json({ error: "Unauthorized" }, 401);

  const expected = await hmacSha256Base64Url(env.ACCESS_TOKEN_SECRET, payloadB64);
  if (!timingSafeEqual(sigB64, expected)) return json({ error: "Unauthorized" }, 401);

  let payload;
  try { payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(payloadB64))); }
  catch { return json({ error: "Unauthorized" }, 401); }

  const now = Math.floor(Date.now() / 1000);
  if (!payload?.exp || now >= payload.exp) return json({ error: "Session expired" }, 401);

  return null;
}

async function hmacSha256Base64Url(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return base64UrlEncode(new Uint8Array(sig));
}

function base64UrlEncode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(b64url) {
  const b64 = b64url.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64url.length + 3) % 4);
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function timingSafeEqual(a, b) {
  a = String(a); b = String(b);
  const len = Math.max(a.length, b.length);
  let diff = a.length ^ b.length;
  for (let i = 0; i < len; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}
