// ── PROMPTO PROXY API v2 ──
// Fixes: rate limiting, JSON.parse safety, request timeout, CORS hardening, injection guard

const ANTHROPIC_URL = 'https://api.anthropic.com/v1/messages';
const API_TIMEOUT_MS = 12000;

// ── UPSTASH REDIS RATE LIMITING ──
// Persistent across cold starts — unlike in-memory Maps which reset every deployment.
// Set UPSTASH_REDIS_REST_URL and UPSTASH_REDIS_REST_TOKEN in Vercel env vars.
// Free tier at upstash.com handles 10,000 requests/day — plenty for early stage.
const RATE_WINDOW_SEC = 60;   // 1-minute sliding window
const RATE_MAX_ANALYZE = 30;  // 30 analyses per minute per IP
const RATE_MAX_BUILD   = 10;  // 10 builds per minute per IP (more expensive)

async function checkRateLimit(ip, action) {
  const redisUrl   = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;

  // If Upstash not configured, allow all (degraded mode — log warning)
  if (!redisUrl || !redisToken) {
    console.warn('Upstash not configured — rate limiting disabled');
    return { allowed: true, remaining: 99 };
  }

  const max = action === 'build' ? RATE_MAX_BUILD : RATE_MAX_ANALYZE;
  const key = `prompto:rl:${action}:${ip}`;

  try {
    // Upstash REST API — INCR + EXPIRE in a pipeline (atomic)
    const res = await fetch(`${redisUrl}/pipeline`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${redisToken}`,
        'Content-Type':  'application/json',
      },
      body: JSON.stringify([
        ['INCR', key],
        ['EXPIRE', key, RATE_WINDOW_SEC, 'NX'],
      ]),
    });

    if (!res.ok) {
      console.error('Upstash error:', res.status);
      return { allowed: true, remaining: 99 };
    }

    const data = await res.json();
    // LOW 12: Validate array structure before accessing
    const count = (Array.isArray(data) && data[0]?.result) ? data[0].result : 0;
    const remaining = Math.max(0, max - count);
    return { allowed: count <= max, remaining };
  } catch (e) {
    console.error('Rate limit check failed:', e.message);
    return { allowed: true, remaining: 99 }; // fail open on Upstash error
  }
}

// ── EXTENSION ID WHITELIST ──
// After publishing to Chrome Web Store, add your extension ID here.
// Get it from chrome://extensions after loading unpacked.
// Leave empty during development — CORS will allow all chrome-extension:// origins.
const ALLOWED_EXTENSION_IDS = [
  // 'abcdefghijklmnopqrstuvwxyz123456'  // <-- paste your extension ID here
];

// ── CORS ──
function corsHeaders(req) {
  const origin = req.headers.get('origin') || '';
  let allowed = false;

  if (ALLOWED_EXTENSION_IDS.length === 0) {
    // Dev mode — allow any chrome extension
    allowed = origin.startsWith('chrome-extension://');
  } else {
    // Production — only allow whitelisted extension ID
    allowed = ALLOWED_EXTENSION_IDS.some(id => origin === `chrome-extension://${id}`);
  }

  return {
    'Access-Control-Allow-Origin':  allowed ? origin : 'null',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Prompto-Action',
    'Access-Control-Max-Age':       '86400',
  };
}

// ── INJECTION GUARD ──
// Prevents user prompts from hijacking the system prompt
function sanitizePrompt(text) {
  if (typeof text !== 'string') return '';
  return text
    .slice(0, 4000)
    .replace(/<\|.*?\|>/g, '')               // OpenAI injection tokens
    .replace(/\[INST\]|\[\/INST\]/gi, '')    // Llama injection tokens
    // LOW 13: word-boundary regex — won't break "ecosystem:" or "file system:"
    .replace(/\b(system|assistant|human):\s*/gi, '')
    .trim();
}

// ── VALIDATE REQUEST ──
function validateBody(body, action) {
  if (!body || typeof body !== 'object') return 'Invalid request body';
  if (action === 'analyze') {
    if (!body.prompt || typeof body.prompt !== 'string') return 'Missing prompt';
    return null;
  }
  if (action === 'build') {
    if (!body.prompt || typeof body.prompt !== 'string') return 'Missing prompt';
    if (!body.answers || typeof body.answers !== 'object') return 'Missing answers';
    // MED 7: Limit answers object to prevent abuse
    const keys = Object.keys(body.answers);
    if (keys.length > 10) return 'Too many answers';
    const totalLen = keys.reduce((sum, k) => sum + k.length + String(body.answers[k]).length, 0);
    if (totalLen > 2000) return 'Answers too large';
    return null;
  }
  return 'Unknown action';
}

// ── SAFE JSON PARSE ──
function safeParseJSON(text) {
  try {
    const clean = text.trim()
      .replace(/^```json\s*/i, '')
      .replace(/\s*```$/i, '');
    return { data: JSON.parse(clean), error: null };
  } catch (e) {
    return { data: null, error: `Invalid JSON: ${e.message}` };
  }
}

// ── FETCH WITH TIMEOUT ──
async function fetchWithTimeout(url, options, timeoutMs) {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(id);
    return res;
  } catch (e) {
    clearTimeout(id);
    if (e.name === 'AbortError') throw new Error('Request timed out after ' + timeoutMs + 'ms');
    throw e;
  }
}

// ── SYSTEM PROMPTS ──
const ANALYZE_SYSTEM = `You are Prompto, an AI prompt coach. A user is typing a prompt into an AI tool.

Read their prompt and return ONE focused coaching tip — the single most important thing missing.

SCORING (be strict — do not inflate):
90-100: Specific topic + audience/context + format or level. Ready to send.
70-89:  Clear intent, most key details present. Minor gaps only.
50-69:  Intent clear but important context or specifics missing.
30-49:  Intent detectable but most details absent.
0-29:   Too vague to produce useful output.

"Write a research report" = 35. "Write a 2000-word undergraduate report on X in APA format" = 88.

COACHING PRIORITY (fix highest-impact gap first):
1. Topic specificity
2. Audience or context
3. Level or depth (academic level, expertise)
4. Output format
5. Length
6. Tone or constraints

SPECIAL CASES:
- Greeting/social only → status: "not_a_prompt"
- Score 85+ and nothing important missing → status: "strong", coaching: null
- Fewer than 4 meaningful words → status: "too_short"

Your response must be a single JSON object. No text before it. No text after it. No markdown fences.
Schema:
{
  "status": "coaching" | "strong" | "not_a_prompt" | "too_short",
  "score": 0-100,
  "score_label": "Strong" | "Good start" | "Getting there" | "Too vague",
  "intent": "short phrase e.g. 'Research report'",
  "coaching": {
    "type": "topic" | "audience" | "level" | "format" | "length" | "constraint",
    "headline": "Under 6 words — the question",
    "body": "One sentence — specific to their prompt, explains exactly what to add and why.",
    "options": ["3-5 realistic choices specific to their situation"],
    "inline_suggestion": "short hint e.g. '— undergraduate, APA citations, 2000 words'"
  } | null,
  "positive": "One specific thing done well, or null"
}
Respond with JSON only. Start your response with { and end with }. Nothing else.`;

const BUILD_SYSTEM = `You are a prompt engineer. A user wrote a prompt and answered one clarifying question.
Incorporate their answer naturally into a complete, improved prompt.

RULES:
- Keep their exact voice and style — never formalize casual writing
- Do not add: "comprehensive", "leverage", "as an AI", "certainly", "please note"
- Only add information that genuinely improves output quality
- Be as concise as possible while being complete

The diff array segments the result: "original" = text kept exactly from user, "added" = new content you added.

Respond with JSON only. Start your response with { and end with }. Nothing else.
Schema: {"enhanced": "the complete improved prompt", "diff": [{"type": "original" | "added", "text": "..."}]}`;

// ── MAIN HANDLER ──
export default async function handler(req) {
  if (req.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders(req) });
  }

  if (req.method !== 'POST') {
    return new Response('Method not allowed', { status: 405, headers: corsHeaders(req) });
  }

  const headers = corsHeaders(req);

  // Action header required
  const action = req.headers.get('x-prompto-action');
  if (!action) {
    return new Response(JSON.stringify({ ok: false, error: 'Missing X-Prompto-Action' }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...headers } });
  }

  // Rate limiting — persistent via Upstash Redis
  const ip = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';

  // Structured request log — visible in Vercel function logs
  console.log(JSON.stringify({
    ts:     new Date().toISOString(),
    action,
    ip:     ip.slice(0, 15), // truncate for privacy
    ua:     (req.headers.get('user-agent') || '').slice(0, 60),
  }));

  const { allowed, remaining } = await checkRateLimit(ip, action);
  if (!allowed) {
    return new Response(
      JSON.stringify({ ok: false, error: 'Too many requests — please wait a minute.' }),
      {
        status: 429,
        headers: {
          'Content-Type':           'application/json',
          'X-RateLimit-Remaining':  '0',
          'Retry-After':            String(RATE_WINDOW_SEC),
          ...headers,
        },
      }
    );
  }

  // Parse body safely
  let body;
  try { body = await req.json(); }
  catch {
    return new Response(JSON.stringify({ ok: false, error: 'Invalid JSON body' }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...headers } });
  }

  // Validate
  const validErr = validateBody(body, action);
  if (validErr) {
    return new Response(JSON.stringify({ ok: false, error: validErr }),
      { status: 400, headers: { 'Content-Type': 'application/json', ...headers } });
  }

  // Env check
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return new Response(JSON.stringify({ ok: false, error: 'Server configuration error' }),
      { status: 500, headers: { 'Content-Type': 'application/json', ...headers } });
  }

  // Build Anthropic request
  let systemPrompt, userMessage, maxTokens;

  if (action === 'analyze') {
    const cleanPrompt = sanitizePrompt(body.prompt);
    systemPrompt = ANALYZE_SYSTEM;
    userMessage  = `Platform: ${String(body.platform || 'unknown').slice(0, 50)}.\n\nUser prompt: "${cleanPrompt}"`;
    maxTokens    = 600;
  } else {
    const cleanPrompt = sanitizePrompt(body.prompt);
    // Sanitize answers too
    const cleanAnswers = Object.fromEntries(
      Object.entries(body.answers)
        .slice(0, 5) // max 5 answers
        .map(([k, v]) => [sanitizePrompt(String(k)), sanitizePrompt(String(v))])
    );
    const answersText = Object.entries(cleanAnswers)
      .filter(([, v]) => v)
      .map(([k, v]) => `- ${k}: ${v}`)
      .join('\n');
    systemPrompt = BUILD_SYSTEM;
    userMessage  = `Original prompt: "${cleanPrompt}"\n\nUser's answer:\n${answersText}`;
    maxTokens    = 800;
  }

  // Call Anthropic with timeout
  try {
    const anthropicRes = await fetchWithTimeout(
      ANTHROPIC_URL,
      {
        method: 'POST',
        headers: {
          'Content-Type':      'application/json',
          'x-api-key':         apiKey,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model:      'claude-haiku-4-5-20251001',
          max_tokens: maxTokens,
          system:     systemPrompt,
          messages:   [{ role: 'user', content: userMessage }],
        }),
      },
      API_TIMEOUT_MS
    );

    if (!anthropicRes.ok) {
      const errText = await anthropicRes.text().catch(() => 'unknown');
      console.error('Anthropic error:', anthropicRes.status, errText);
      return new Response(
        JSON.stringify({ ok: false, error: `AI service error (${anthropicRes.status})` }),
        { status: 502, headers: { 'Content-Type': 'application/json', ...headers } }
      );
    }

    const anthropicData = await anthropicRes.json();
    const rawText = anthropicData?.content?.[0]?.text || '';

    // Safe JSON parse — Fix for proxy crash on malformed JSON
    const { data, error: parseError } = safeParseJSON(rawText);
    if (parseError) {
      console.error('JSON parse error:', parseError, 'Raw:', rawText.slice(0, 200));
      return new Response(
        JSON.stringify({ ok: false, error: 'Failed to parse AI response' }),
        { status: 502, headers: { 'Content-Type': 'application/json', ...headers } }
      );
    }

    return new Response(
      JSON.stringify({ ok: true, data }),
      { status: 200, headers: { 'Content-Type': 'application/json', ...headers } }
    );

  } catch (err) {
    console.error('Proxy error:', err.message);
    const isTimeout = err.message.includes('timed out');
    return new Response(
      JSON.stringify({ ok: false, error: isTimeout ? 'AI took too long to respond' : 'Internal server error' }),
      { status: isTimeout ? 504 : 500, headers: { 'Content-Type': 'application/json', ...headers } }
    );
  }
}

export const config = { runtime: 'edge' };
