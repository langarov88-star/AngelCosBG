export async function onRequestPost({ request, env }) {
  const authErr = await requireAuth(request, env);
  if (authErr) return authErr;

  if (!env?.OPENAI_API_KEY) {
    return json({ error: "OPENAI_API_KEY missing in env" }, 500);
  }

  let body;
  try { body = await request.json(); }
  catch { return json({ error: "Invalid JSON body" }, 400); }

  const shopName = String(body.shop_name || "").trim();
  const tone = String(body.tone || "").trim();
  const productInfo = String(body.product_info || "").trim();
  const competitorNotes = String(body.competitor_notes || "").trim();

  if (!productInfo) return json({ error: "Missing product_info" }, 400);

  // ограничаваме входа, за да не гръмне токени
  const productInfoTrim = productInfo.slice(0, 9000);
  const competitorTrim = competitorNotes.slice(0, 12000);

  const instructions = `Ти си експерт копирайтър за e-commerce и SEO за България.
ЦЕЛ: генерирай листинг за angelcosmetics.bg на български език, ориентиран към конверсия и UX.

ВАЖНИ ПРАВИЛА:
- Не копирай 1:1 текстове от източници/конкуренти. Използвай ги само като ориентир.
- Без медицински твърдения, без “лекува”, без гаранции, без “клинично доказано” ако не е дадено.
- Ясни, естествени изречения. Без спам с ключови думи.
- Без HTML. Без емоджита. Без ръчни булети със символи. Ако правиш списъци – само нови редове.

ИЗХОДНА СТРУКТУРА (точно така, в този ред):

Заглавие
Кратко описание
Детайлно описание

В "Детайлно описание" задължително включи секции (точно тези заглавия):
Описание
Ползи
Подходящ за
Активни съставки / Технологии
Как се използва
Препоръка за най-добри резултати
FAQ

ФОРМАТ:
- Заглавията да са на отделен ред.
- Под всяко заглавие – текст/редове.
- FAQ: 3–6 въпроса и отговора (въпрос на ред, после отговор на следващ ред).`;

  const brandLine = shopName ? `Бранд/магазин: ${shopName}\n` : "";
  const toneLine = tone ? `Тон/стил: ${tone}\n` : "";

  const input = `${brandLine}${toneLine}
ТВОЯТ ПРОДУКТ (основен източник):
${productInfoTrim}

ОРИЕНТИР ОТ ИЗТОЧНИЦИ (НЕ копирай 1:1):
${competitorTrim || "(няма)"}

ЗАДАЧА:
1) Напиши "Заглавие" – кратко, ясно, продаващо, с ключова полза + тип продукт + марка/серия ако има.
2) "Кратко описание" – 2–4 изречения за най-важното.
3) "Детайлно описание" със секции: Описание, Ползи, Подходящ за, Активни съставки / Технологии, Как се използва, Препоръка за най-добри резултати, FAQ.
4) Не използвай забранени твърдения. Ако липсва точна информация (напр. точни активни съставки), формулирай предпазливо (напр. "може да съдържа" НЕ; по-добре: "с формула, насочена към...") и не измисляй конкретика.`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 45000);

    const resp = await fetch("https://api.openai.com/v1/responses", {
      method: "POST",
      signal: controller.signal,
      headers: {
        "Authorization": `Bearer ${env.OPENAI_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: env.OPENAI_MODEL || "gpt-5.2",
        instructions,
        input,
        max_output_tokens: 2200,
        temperature: 0.7,
        text: { format: { type: "text" } }
      })
    }).finally(() => clearTimeout(timeout));

    const contentType = resp.headers.get("content-type") || "";
    const data = contentType.includes("application/json")
      ? await resp.json()
      : { raw: await resp.text() };

    if (!resp.ok) {
      const msg = data?.error?.message || data?.raw || "OpenAI error";
      return json({ error: msg }, resp.status);
    }

    const output = extractText(data);
    if (!output) {
      return json({ error: "Empty output from OpenAI", debug: data }, 500);
    }

    return json({ output }, 200);

  } catch (e) {
    const msg =
      e?.name === "AbortError"
        ? "Timeout while calling OpenAI (45s). Try again."
        : String(e?.message || e || "Server error");
    return json({ error: msg }, 500);
  }
}

/* ---------------- Response text extractor ---------------- */

function extractText(data) {
  if (typeof data?.output_text === "string" && data.output_text.trim()) {
    return data.output_text.trim();
  }

  const out = data?.output;
  if (Array.isArray(out)) {
    const parts = [];
    for (const item of out) {
      const content = item?.content;
      if (Array.isArray(content)) {
        for (const c of content) {
          if (c?.type === "output_text" && typeof c?.text === "string") parts.push(c.text);
          else if (typeof c?.text === "string") parts.push(c.text);
        }
      }
    }
    const joined = parts.join("\n").trim();
    if (joined) return joined;
  }

  return "";
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
