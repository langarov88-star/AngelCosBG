export async function onRequestPost({ request, env }) {
  // CORS headers за публичен достъп (чатът е за посетители на сайта)
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type"
  };

  // Handle preflight
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (!env?.ANTHROPIC_API_KEY) {
    return json({ error: "ANTHROPIC_API_KEY missing in env" }, 500, corsHeaders);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid JSON body" }, 400, corsHeaders);
  }

  const userMessage = String(body.message || "").trim();
  const conversationHistory = Array.isArray(body.history) ? body.history : [];

  if (!userMessage) {
    return json({ error: "Missing message" }, 400, corsHeaders);
  }

  // Ограничаваме дължината на съобщението
  const userMessageTrim = userMessage.slice(0, 2000);

  // Ограничаваме историята до последните 20 съобщения
  const historyTrim = conversationHistory.slice(-20).map(msg => ({
    role: msg.role === "assistant" ? "assistant" : "user",
    content: String(msg.content || "").slice(0, 2000)
  }));

  // System prompt за AI асистента
  const systemPrompt = `Ти си AI асистент на Angel Cosmetics (angelcosmetics.bg) - онлайн магазин за козметика в България.

ТВОЯТА РОЛЯ:
- Помагаш на клиентите с въпроси за козметични продукти
- Даваш препоръки за грижа за кожата и косата
- Обясняваш как се използват различни козметични продукти
- Помагаш при избор на подходящи продукти според типа кожа/коса
- Отговаряш на въпроси за съставки в козметиката
- Даваш съвети за beauty рутини

ПРАВИЛА:
- Отговаряй САМО на български език
- Бъди приятелски настроен и професионален
- Не давай медицински съвети - при кожни проблеми препоръчвай консултация с дерматолог
- Не измисляй конкретни продукти от магазина ако не ги знаеш
- Ако не знаеш нещо, кажи честно
- Отговорите да са кратки и ясни (до 2-3 параграфа обикновено)
- Можеш да питаш уточняващи въпроси ако е нужно

ИНФОРМАЦИЯ ЗА МАГАЗИНА:
- Angel Cosmetics е онлайн магазин за козметика в България
- Предлага широка гама от продукти за грижа за кожата и косата
- Има програма за лоялни клиенти с отстъпки и подаръци
- Сайт: angelcosmetics.bg

Започни разговора приятелски и помогни на клиента!`;

  // Подготвяме съобщенията за Claude API
  const messages = [
    ...historyTrim,
    { role: "user", content: userMessageTrim }
  ];

  try {
    const response = await callClaude(env, systemPrompt, messages);

    return json({
      response: response,
      success: true
    }, 200, corsHeaders);

  } catch (e) {
    const msg = e?.name === "AbortError"
      ? "Timeout при заявката. Моля, опитай отново."
      : String(e?.message || e || "Server error");
    return json({ error: msg }, 500, corsHeaders);
  }
}

// Handle OPTIONS requests for CORS
export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

/* ---------------- Claude API call helper ---------------- */

async function callClaude(env, systemPrompt, messages) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000); // 30 секунди timeout

  const payload = {
    model: env.CLAUDE_MODEL || "claude-sonnet-4-20250514",
    max_tokens: 1024,
    system: systemPrompt,
    messages: messages
  };

  const resp = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    signal: controller.signal,
    headers: {
      "x-api-key": env.ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01",
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  }).finally(() => clearTimeout(timeout));

  const contentType = resp.headers.get("content-type") || "";
  const data = contentType.includes("application/json")
    ? await resp.json()
    : { raw: await resp.text() };

  if (!resp.ok) {
    const msg = data?.error?.message || data?.raw || "Claude API error";
    const err = new Error(msg);
    err.status = resp.status;
    err.data = data;
    throw err;
  }

  // Извличаме текста от отговора
  const content = data?.content;
  if (Array.isArray(content)) {
    for (const block of content) {
      if (block?.type === "text" && typeof block?.text === "string") {
        return block.text.trim();
      }
    }
  }

  return "";
}

/* ---------------- JSON helper ---------------- */

function json(obj, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders
    }
  });
}
