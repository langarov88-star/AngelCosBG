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

  // --- Web search options (optional; default ON) ---
  const enableWebSearch = body?.enable_web_search !== false;
  const allowedDomains = sanitizeAllowedDomains(body?.allowed_domains);
  const webQuery =
    String(body?.web_query || "").trim() ||
    normalizeSpaces(`${shopName} ${productInfoTrim}`.slice(0, 260));

  const BONUS = "Бонус ОТСТЪПКИ + подаръци за лоялни клиенти. Топ цени.";

  const instructions = `Ти си експерт копирайтър за e-commerce и SEO за България.
ЦЕЛ: генерирай продуктов листинг за angelcosmetics.bg на български език, ориентиран към конверсия и UX.

КРИТИЧНИ ПРАВИЛА:
- Не копирай 1:1 текстове от източници/конкуренти. Използвай ги само като ориентир.
- Без медицински твърдения, без “лекува”, без гаранции, без “клинично доказано” ако не е дадено.
- Без HTML. Без емоджита. Без булети/тирета/номерация. Ако има списъци — само нов ред.
- Не измисляй конкретика. Ако липсва факт (напр. точни активни съставки), пиши общо и предпазливо.

ИЗХОД: Върни САМО секциите по-долу, точно в този ред. Всяко заглавие е на отделен ред, след него съдържание.

СЕКЦИИ (точно тези заглавия):
H1 Заглавие
Meta Title
Meta Description
HOOK описание
ДЪЛГО ОПИСАНИЕ
Ползи
Подходящ за
Активни съставки / Технологии
Как се използва
Препоръка за най-добри резултати
FAQ

СПЕЦИФИЧНИ ИЗИСКВАНИЯ:
H1 Заглавие:
- Формула: [ключов проблем/решение + тип продукт + основна активна съставка (ако е известна) + бранд + модел/серия + разфасовка (ml)]
- Ако липсва активна съставка или разфасовка (ml) — пропусни ги, не измисляй.

Meta Title:
- Формула: [Бранд + Продукт + кратка ключова полза] | Angel Cosmetics BG

Meta Description:
- [Бранд + продукт + основна полза + ключови думи за SEO + целева аудитория + разфасовки + ефект] Бонус ОТСТЪПКИ + подаръци за лоялни клиенти. Топ цени.
- 150–160 символа ОБЩО (включително интервали).
- Задължително завършва с точно тази фраза: ${BONUS}
- Реалистично, без “лекува”, без гаранции, без прекалени обещания.

HOOK описание:
- 1–2 изречения, силно, продажбено, реалистично, ненатрапчиво.

ДЪЛГО ОПИСАНИЕ:
- SEO + ROI + UX: предназначение, как действа (общо/коректно), реалистични ефекти, доверие, консултантски тон.

Ползи:
- Само по редове (нов ред), без символи, без тирета.

Подходящ за:
- По редове: тип кожа/коса, проблеми, сезонност (ако е релевантно), възраст (ако е релевантно).

Активни съставки / Технологии:
- По редове, формат: "Съставка: кратка полза" (без тирета).

Как се използва:
- Кратки, ясни инструкции.

Препоръка за най-добри резултати:
- Cross-sell предложение (категория/тип продукт), без да измисляш конкретен продукт ако не е даден.

FAQ:
- 3–5 въпроса.
- Въпрос на ред, отговор на следващ ред. Без номерация.`;

  const brandLine = shopName ? `Бранд/магазин: ${shopName}\n` : "";
  const toneLine = tone ? `Тон/стил: ${tone}\n` : "";

  // --- Web facts enrichment (step A) ---
  let webFacts = "";
  let webSources = []; // масив от {url,title}
  if (enableWebSearch) {
    try {
      const enriched = await collectWebFacts(env, {
        query: webQuery,
        productInfo: productInfoTrim,
        allowedDomains
      });
      webFacts = (enriched?.facts || "").slice(0, 6000);
      webSources = Array.isArray(enriched?.sources) ? enriched.sources : [];
    } catch {
      webFacts = "";
      webSources = [];
    }
  }

  const input = `${brandLine}${toneLine}
ТВОЯТ ПРОДУКТ (основен източник):
${productInfoTrim}

ФАКТИ ОТ УЕБ (ориентир, НЕ копирай 1:1):
${webFacts || "(няма)"}

ОРИЕНТИР ОТ ИЗТОЧНИЦИ (НЕ копирай 1:1):
${competitorTrim || "(няма)"}

ЗАДАЧА:
Генерирай листинг по горните секции. Спазвай всички правила.`;

  try {
    // 1) Основна генерация (без задължително web_search тук — вече имаме webFacts)
    const data1 = await callOpenAI(env, instructions, input, {
      max_output_tokens: 2600,
      temperature: 0.6,
      timeoutMs: 45000
    });

    const output1 = extractText(data1);
    if (!output1) return json({ error: "Empty output from OpenAI", debug: data1 }, 500);

    // 2) Проверка и “ремонт” на Meta Description (150–160 + бонус фраза)
    const fixed = await ensureMetaDescription(output1, env, {
      productInfo: productInfoTrim,
      bonus: BONUS
    });

    // НОВО: "ресурси" (на български) + запазваме и старите полета
    return json({
      output: fixed,
      ресурси: webSources,                 // <-- новото поле (url + title)
      sources: webSources,                 // (по желание) англ. еквивалент
      web_sources: webSources.map(s => s.url) // (по желание) само URL-и
    }, 200);

  } catch (e) {
    const msg =
      e?.name === "AbortError"
        ? "Timeout while calling OpenAI. Try again."
        : String(e?.message || e || "Server error");
    return json({ error: msg }, 500);
  }
}

/* ---------------- Meta Description fixer ---------------- */

const HEADINGS = [
  "H1 Заглавие",
  "Meta Title",
  "Meta Description",
  "HOOK описание",
  "ДЪЛГО ОПИСАНИЕ",
  "Ползи",
  "Подходящ за",
  "Активни съставки / Технологии",
  "Как се използва",
  "Препоръка за най-добри резултати",
  "FAQ"
];

function parseSections(text) {
  const map = {};
  for (const h of HEADINGS) map[h] = [];

  const lines = String(text || "").replace(/\r/g, "").split("\n");
  let current = null;

  for (const raw of lines) {
    const line = raw.trimEnd();
    const key = HEADINGS.find(h => line.trim() === h);
    if (key) {
      current = key;
      continue;
    }
    if (!current) continue;
    map[current].push(raw);
  }
  return map;
}

function rebuildFromSections(sections) {
  const out = [];
  for (const h of HEADINGS) {
    out.push(h);
    const body = (sections[h] || []).join("\n").trim();
    if (body) out.push(body);
    out.push("");
  }
  return out.join("\n").trim();
}

function normalizeSpaces(s) {
  return String(s || "").replace(/\s+/g, " ").trim();
}

function endsWithBonus(meta, bonus) {
  return normalizeSpaces(meta).endsWith(normalizeSpaces(bonus));
}

async function ensureMetaDescription(fullOutput, env, { productInfo, bonus }) {
  const sections = parseSections(fullOutput);
  const metaRaw = (sections["Meta Description"] || []).join("\n").trim();

  // ако секциите не са разпознати -> връщаме както е (по-добре от това да чупим)
  if (!metaRaw && !fullOutput.includes("Meta Description")) return fullOutput;

  const metaNorm = normalizeSpaces(metaRaw);
  const metaLen = metaNorm.length;

  const needsFix =
    metaLen < 150 ||
    metaLen > 160 ||
    !endsWithBonus(metaNorm, bonus);

  if (!needsFix) return fullOutput;

  const fixInstructions = `Ти си SEO copywriter на български.
Задача: напиши Meta Description за продуктова страница.

КРИТИЧНИ ИЗИСКВАНИЯ:
- 150–160 символа ОБЩО (включително интервали).
- Задължително завършва с точно: ${bonus}
- Без медицински твърдения, без гаранции, без “лекува”.
- Реалистично, продаващо, с ключови думи естествено.
- Върни САМО meta description текста (без кавички, без заглавия).`;

  const fixInput = `ДАННИ ЗА ПРОДУКТА:
${productInfo}

ТЕКУЩ (грешен) META DESCRIPTION:
${metaRaw || "(липсва)"}

НАПИШИ НОВ, КОЙТО СПАЗВА ИЗИСКВАНИЯТА.`;

  const data2 = await callOpenAI(env, fixInstructions, fixInput, {
    max_output_tokens: 220,
    temperature: 0.4,
    timeoutMs: 30000
  });

  let metaFixed = normalizeSpaces(extractText(data2));

  // ако моделът върне нещо странно – fallback към старото
  if (!metaFixed) return fullOutput;

  // гарантираме бонус в края (ако случайно го е пропуснал)
  if (!endsWithBonus(metaFixed, bonus)) {
    const b = normalizeSpaces(bonus);
    metaFixed = normalizeSpaces(metaFixed.replace(new RegExp(`${escapeRegExp(b)}$`), ""));
    metaFixed = normalizeSpaces(metaFixed + " " + b);
  }

  // ако след това пак е извън 150–160, не правим безкрайни опити – оставяме каквото е, но сменяме секцията
  sections["Meta Description"] = [metaFixed];

  return rebuildFromSections(sections);
}

function escapeRegExp(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/* ---------------- Web search enrichment helpers ---------------- */

function stripInlineCitations(text) {
  // маха типични inline маркери като [1], [2] ако се появят
  return String(text || "")
    .replace(/\s*\[\d+\]\s*/g, " ")
    .replace(/\s{2,}/g, " ")
    .trim();
}

function sanitizeAllowedDomains(input) {
  if (!Array.isArray(input)) return null;

  const out = [];
  for (const raw of input) {
    let d = String(raw || "").trim().toLowerCase();
    if (!d) continue;

    d = d.replace(/^https?:\/\//, "");
    d = d.split("/")[0].split("?")[0].split("#")[0].trim();

    // basic validation
    if (!d || d.includes(" ") || !d.includes(".")) continue;

    out.push(d);
  }

  const uniq = Array.from(new Set(out)).slice(0, 100);
  return uniq.length ? uniq : null;
}

// НОВО: връща масив от {url,title}
function extractWebSourceObjects(data) {
  const byUrl = new Map();
  const out = data?.output;
  if (!Array.isArray(out)) return [];

  for (const item of out) {
    if (item?.type !== "web_search_call") continue;

    const sources = item?.action?.sources;
    if (!Array.isArray(sources)) continue;

    for (const s of sources) {
      let url = "";
      let title = "";

      if (typeof s === "string") {
        url = s;
      } else if (s && typeof s === "object") {
        url = s.url || s.source?.url || "";
        title = s.title || s.source?.title || "";
      }

      url = String(url || "").trim();
      title = String(title || "").trim();
      if (!url) continue;

      if (!byUrl.has(url)) {
        byUrl.set(url, { url, title });
      }
    }
  }

  return Array.from(byUrl.values()).slice(0, 50);
}

async function collectWebFacts(env, { query, productInfo, allowedDomains }) {
  const factInstructions = `Ти имаш достъп до web search.
Цел: извлечи проверими факти за продукт, без да копираш изречения 1:1.

КРИТИЧНИ ПРАВИЛА:
- Използвай web search и отвори релевантни страници, ако е нужно.
- Извличай само факти, които са ясни и еднозначни. Ако не си сигурен – пропусни.
- Не прави медицински твърдения.
- Не давай линкове, цитати или бележки. Без HTML.

ИЗХОД:
Върни САМО редове с факти (по един факт на ред). Без заглавия.`;

  const factInput = `Търси за:
${query}

Контекст от нас:
${productInfo}`;

  const tools = [
    allowedDomains?.length
      ? { type: "web_search", filters: { allowed_domains: allowedDomains } }
      : { type: "web_search" }
  ];

  const data = await callOpenAI(env, factInstructions, factInput, {
    max_output_tokens: 700,
    temperature: 0.2,
    timeoutMs: 45000,
    reasoning: { effort: "low" },
    tools,
    tool_choice: "auto",
    include: ["web_search_call.action.sources"]
  });

  const facts = stripInlineCitations(extractText(data));
  const sources = extractWebSourceObjects(data);

  return { facts, sources };
}

/* ---------------- OpenAI call helper (Responses API) ---------------- */

async function callOpenAI(
  env,
  instructions,
  input,
  { max_output_tokens, temperature, timeoutMs, reasoning, tools, tool_choice, include }
) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs || 45000);

  const payload = {
    model: env.OPENAI_MODEL || "gpt-5.2",
    instructions,
    input,
    max_output_tokens: max_output_tokens ?? 2200,
    temperature: temperature ?? 0.7,
    text: { format: { type: "text" } }
  };

  if (reasoning) payload.reasoning = reasoning;
  if (tools) payload.tools = tools;
  if (tool_choice) payload.tool_choice = tool_choice;
  if (include) payload.include = include;

  const resp = await fetch("https://api.openai.com/v1/responses", {
    method: "POST",
    signal: controller.signal,
    headers: {
      "Authorization": `Bearer ${env.OPENAI_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  }).finally(() => clearTimeout(timeout));

  const contentType = resp.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await resp.json()
    : { raw: await resp.text() };

  if (!resp.ok) {
    const msg = data?.error?.message || data?.raw || "OpenAI error";
    const err = new Error(msg);
    err.status = resp.status;
    err.data = data;
    throw err;
  }
  return data;
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
