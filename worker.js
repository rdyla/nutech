// Cloudflare Worker — Zoom Phone SMS middleware (3-legged OAuth)
// Required env vars/secrets:
// - ZOOM_OAUTH_CLIENT_ID
// - ZOOM_OAUTH_CLIENT_SECRET
// - ZOOM_OAUTH_REDIRECT_URL   (e.g. https://nutech.itcontact-521.workers.dev/zoom/callback)
// - ZOOM_SMS_FROM_E164        (e.g. +12396887170)
// - ZVA_SHARED_SECRET
//
// Required binding:
// - TOKENS_KV (KV namespace binding)
//
// Work order wizard - Open new ticket endpoint
// Bearer token auth
// Required env secret: WORK_ORDER_WIZARD_API_TOKEN

const ZOOM_OAUTH_AUTHORIZE_URL = "https://zoom.us/oauth/authorize";
const ZOOM_OAUTH_TOKEN_URL = "https://zoom.us/oauth/token";
const ZOOM_API_BASE = "https://api.zoom.us/v2";
const WOW_WORK_ORDERS_URL = "https://nutech.cloud/api/external/work-orders";

// Helpers
function normalizeAnyPhone(input) {
  if (!input) return null;
  const digits = String(input).replace(/\D/g, "");
  // If already looks like E.164 with country code (10+ digits), best-effort:
  if (String(input).trim().startsWith("+") && digits.length >= 10) return `+${digits}`;
  // US best-effort:
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  if (digits.length === 10) return `+1${digits}`;
  // fallback: return original trimmed if not crazy short
  const t = String(input).trim();
  return t.length >= 7 ? t : null;
}

async function createWorkOrder(env, body) {
  if (!env.WORK_ORDER_WIZARD_API_TOKEN) {
    return { ok: false, status: 500, error: "Missing WORK_ORDER_WIZARD_API_TOKEN" };
  }

  const resp = await fetch(WOW_WORK_ORDERS_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.WORK_ORDER_WIZARD_API_TOKEN}`,
      "Content-Type": "application/json",
      Accept: "application/json",
    },
    body: JSON.stringify(body),
  });

  const text = await resp.text();
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    parsed = text;
  }

  if (!resp.ok) return { ok: false, status: resp.status, error: parsed };
  return { ok: true, status: resp.status, data: parsed };
}

// In-memory cache (per isolate)
let cachedUserAccessToken = null;
let cachedUserAccessTokenExpMs = 0;

// Very lightweight in-memory rate limiter (per Worker instance)
const rateBucket = new Map(); // key -> {count, resetMs}

// ---------- helpers ----------
function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function withCors(req, res) {
  const origin = req.headers.get("origin") || "*";
  const headers = new Headers(res.headers);
  headers.set("access-control-allow-origin", origin);
  headers.set("access-control-allow-methods", "POST, OPTIONS, GET");
  headers.set("access-control-allow-headers", "content-type, x-zva-secret, authorization");
  headers.set("access-control-max-age", "86400");
  return new Response(res.body, { status: res.status, headers });
}

function normalizeE164US(input) {
  if (!input) return null;
  const digits = String(input).replace(/\D/g, "");
  if (digits.length === 11 && digits.startsWith("1")) return `+${digits}`;
  if (digits.length === 10) return `+1${digits}`;
  if (String(input).startsWith("+") && digits.length >= 10) return `+${digits}`;
  return null;
}

function requireSecret(req, env) {
  const secret =
    req.headers.get("x-zva-secret") ||   // old
    req.headers.get("x_zva_secret") ||   // new (no dashes)
    req.headers.get("secret") ||         // fallback
    "";
  return secret && env.ZVA_SHARED_SECRET && secret === env.ZVA_SHARED_SECRET;
}

function rateLimit(key, { limit = 3, windowSec = 60 } = {}) {
  const now = Date.now();
  const existing = rateBucket.get(key);
  if (!existing || now > existing.resetMs) {
    rateBucket.set(key, { count: 1, resetMs: now + windowSec * 1000 });
    return { ok: true };
  }
  if (existing.count >= limit) {
    const retryAfterSec = Math.ceil((existing.resetMs - now) / 1000);
    return { ok: false, retryAfterSec };
  }
  existing.count += 1;
  return { ok: true };
}

function basicAuthHeader(clientId, clientSecret) {
  return `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
}

// ---------- OAuth flow ----------
function buildAuthorizeUrl(env, state) {
  const u = new URL(ZOOM_OAUTH_AUTHORIZE_URL);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", env.ZOOM_OAUTH_CLIENT_ID);
  u.searchParams.set("redirect_uri", env.ZOOM_OAUTH_REDIRECT_URL);
  u.searchParams.set("state", state);
  return u.toString();
}

async function exchangeCodeForTokens(code, env) {
  const u = new URL(ZOOM_OAUTH_TOKEN_URL);
  u.searchParams.set("grant_type", "authorization_code");
  u.searchParams.set("code", code);
  u.searchParams.set("redirect_uri", env.ZOOM_OAUTH_REDIRECT_URL);

  const resp = await fetch(u.toString(), {
    method: "POST",
    headers: {
      Authorization: basicAuthHeader(env.ZOOM_OAUTH_CLIENT_ID, env.ZOOM_OAUTH_CLIENT_SECRET),
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });

  const text = await resp.text();
  if (!resp.ok) throw new Error(`Token exchange failed ${resp.status}: ${text}`);
  return JSON.parse(text);
}

async function refreshAccessToken(refreshToken, env) {
  const u = new URL(ZOOM_OAUTH_TOKEN_URL);
  u.searchParams.set("grant_type", "refresh_token");
  u.searchParams.set("refresh_token", refreshToken);

  const resp = await fetch(u.toString(), {
    method: "POST",
    headers: {
      Authorization: basicAuthHeader(env.ZOOM_OAUTH_CLIENT_ID, env.ZOOM_OAUTH_CLIENT_SECRET),
      "Content-Type": "application/x-www-form-urlencoded",
    },
  });

  const text = await resp.text();
  if (!resp.ok) throw new Error(`Token refresh failed ${resp.status}: ${text}`);
  return JSON.parse(text);
}

async function getUserAccessToken(env) {
  const now = Date.now();
  if (cachedUserAccessToken && now < cachedUserAccessTokenExpMs - 30_000) {
    return cachedUserAccessToken;
  }

  const raw = await env.TOKENS_KV.get("zoom_sms_sender");
  if (!raw) throw new Error("No stored Zoom OAuth tokens. Visit /zoom/authorize first.");

  const stored = JSON.parse(raw);
  if (!stored.refresh_token) throw new Error("Stored token missing refresh_token.");

  const refreshed = await refreshAccessToken(stored.refresh_token, env);

  // Persist the newest refresh token (Zoom rotates refresh tokens)
  await env.TOKENS_KV.put(
    "zoom_sms_sender",
    JSON.stringify({
      refresh_token: refreshed.refresh_token,
      access_token: refreshed.access_token,
      expires_in: refreshed.expires_in,
      obtained_at: Date.now(),
    })
  );

  cachedUserAccessToken = refreshed.access_token;
  cachedUserAccessTokenExpMs = Date.now() + (refreshed.expires_in || 3600) * 1000;

  return cachedUserAccessToken;
}

// ---------- Zoom SMS ----------
async function sendZoomSmsUserToken({ accessToken, fromE164, toE164, message, senderUserId }) {
  const resp = await fetch("https://api.zoom.us/v2/phone/sms/messages", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      message,
      sender: {
        user_id: senderUserId,        // <-- add back (static)
        phone_number: fromE164
      },
      to_members: [{ phone_number: toE164 }],
    }),
  });

  const text = await resp.text();
  let json;
  try { json = JSON.parse(text); } catch { json = text; }

  if (!resp.ok) return { ok: false, status: resp.status, error: json };
  return { ok: true, status: resp.status, data: json };
}

// ---------- worker ----------
export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // CORS preflight
    if (req.method === "OPTIONS") {
      return withCors(
        req,
        new Response(null, {
          status: 204,
          headers: {
            "access-control-allow-origin": req.headers.get("origin") || "*",
            "access-control-allow-methods": "POST, OPTIONS, GET",
            "access-control-allow-headers": "content-type, x-zva-secret, authorization",
            "access-control-max-age": "86400",
          },
        })
      );
    }

    // health check
    if (req.method === "GET" && url.pathname === "/") {
      return json({ ok: true, service: "zoom-sms-middleware" });
    }

    if (req.method === "GET" && url.pathname === "/debug-kv") {
      const val = await env.TOKENS_KV.get("zoom_sms_sender");
      return json({
        kvBound: !!env.TOKENS_KV,
        hasToken: !!val,
        tokenPreview: val ? JSON.parse(val).obtained_at : null
      });
    }
    
    // ---- OAuth endpoints ----
    if (req.method === "GET" && url.pathname === "/zoom/authorize") {
      const state = crypto.randomUUID();
      // Optional: store state to KV to validate callback (skipped for speed)
      return Response.redirect(buildAuthorizeUrl(env, state), 302);
    }

    if (req.method === "GET" && url.pathname === "/zoom/callback") {
      const code = url.searchParams.get("code");
      if (!code) return new Response("Missing code", { status: 400 });

      try {
        const tokens = await exchangeCodeForTokens(code, env);

        await env.TOKENS_KV.put(
          "zoom_sms_sender",
          JSON.stringify({
            refresh_token: tokens.refresh_token,
            access_token: tokens.access_token,
            expires_in: tokens.expires_in,
            obtained_at: Date.now(),
          })
        );

        return new Response("Zoom OAuth authorized. You can close this tab.", { status: 200 });
      } catch (e) {
        return new Response(`OAuth callback failed: ${e?.message || String(e)}`, { status: 500 });
      }
    }

  // Serve docs from R2: GET /docs/<objectKey>
if (req.method === "GET" && url.pathname.startsWith("/docs/")) {
  // IMPORTANT: object keys may include spaces, so decode
  const key = decodeURIComponent(url.pathname.replace("/docs/", ""));
  if (!key) return new Response("Missing key", { status: 400 });

  // nutech-docs is your R2 binding name (env binding is typically env.NUTECH_DOCS or env["nutech-docs"] depending on how you bound it)
  const bucket = env["nutech-docs"];
  if (!bucket) return new Response("Missing R2 binding", { status: 500 });

  const obj = await bucket.get(key);
  if (!obj) return new Response("Not found", { status: 404 });

  const headers = new Headers();
  obj.writeHttpMetadata(headers);
  headers.set("etag", obj.httpEtag);
  headers.set("cache-control", "public, max-age=3600");

  return new Response(obj.body, { headers });
}

// ---- Work order create endpoint ----
// ---- Work order create endpoint ----
if (req.method === "POST" && url.pathname === "/work-orders/create") {
  if (!requireSecret(req, env)) {
    return withCors(req, json({ ok: false, error: "Unauthorized" }, 401));
  }

  let payload;
  try {
    payload = await req.json();
  } catch {
    return withCors(req, json({ ok: false, error: "Invalid JSON" }, 400));
  }

  const caller_name = String(payload?.caller_name || "").trim();
  const caller_phone_raw = payload?.caller_phone;
  const caller_phone = normalizeAnyPhone(caller_phone_raw);

  const brand = String(payload?.brand || "").trim();
  const store_number = String(payload?.store_number || "").trim();
  let description = String(payload?.description || "").trim();

  if (!caller_name) return withCors(req, json({ ok: false, error: "Missing caller_name" }, 400));
  if (!caller_phone) return withCors(req, json({ ok: false, error: "Missing/invalid caller_phone" }, 400));
  if (!brand) return withCors(req, json({ ok: false, error: "Missing brand" }, 400));
  if (!store_number) return withCors(req, json({ ok: false, error: "Missing store_number" }, 400));
  if (!description) return withCors(req, json({ ok: false, error: "Missing description" }, 400));

  if (description.length > 4000) description = description.slice(0, 4000);

  // Optional: rate-limit by caller phone
  const rl = rateLimit(`wo:${caller_phone}`, { limit: 6, windowSec: 60 });
  if (!rl.ok) {
    return withCors(
      req,
      json({ ok: false, error: "Rate limited", retry_after_seconds: rl.retryAfterSec }, 429, {
        "retry-after": String(rl.retryAfterSec),
      })
    );
  }

  // Worker-generated timestamp
  const call_time = new Date().toISOString();

  const forwardBody = {
    caller_name,
    // keep original formatting if the customer prefers it, otherwise use caller_phone
    caller_phone: String(caller_phone_raw || caller_phone),
    brand,
    store_number,
    call_time,
    description,
  };

  try {
    const result = await createWorkOrder(env, forwardBody);
    if (!result.ok) {
      return withCors(
        req,
        json(
          { ok: false, upstream: "work-order-wizard", status: result.status, error: result.error },
          502
        )
      );
    }

    // Your upstream returns: { success: true, work_order_number: "..." }
    // If you truly don't care about the WO number, just return ok: true
    // (But we can still pass through success for debugging.)
    return withCors(req, json({ ok: true }, 200));

    // If you'd rather return the upstream success flag (still not exposing the number):
    // return withCors(req, json({ ok: true, success: !!result.data?.success }, 200));

  } catch (e) {
    return withCors(req, json({ ok: false, error: e?.message || String(e) }, 500));
  }
}


    // ---- SMS send endpoint ----
    if (req.method !== "POST" || url.pathname !== "/sms/send") {
      return withCors(req, json({ ok: false, error: "Not found" }, 404));
    }

    if (!requireSecret(req, env)) {
      return withCors(req, json({ ok: false, error: "Unauthorized" }, 401));
    }

    let payload;
    try {
      payload = await req.json();
    } catch {
      return withCors(req, json({ ok: false, error: "Invalid JSON" }, 400));
    }

    const toE164 = normalizeE164US(payload?.to);
    if (!toE164) return withCors(req, json({ ok: false, error: "Invalid 'to' phone number" }, 400));

    let message = String(payload?.message || "").trim();
    if (!message) return withCors(req, json({ ok: false, error: "Missing 'message'" }, 400));
    if (message.length > 480) message = message.slice(0, 480);

    const rl = rateLimit(`to:${toE164}`, { limit: 3, windowSec: 60 });
    if (!rl.ok) {
      return withCors(
        req,
        json({ ok: false, error: "Rate limited", retry_after_seconds: rl.retryAfterSec }, 429, {
          "retry-after": String(rl.retryAfterSec),
        })
      );
    }

    const fromE164 = env.ZOOM_SMS_FROM_E164 || "+12396887170";

    try {
      const senderUserId = env.ZOOM_SMS_SENDER_USER_ID;
      if (!senderUserId) {
        return withCors(req, json({ ok: false, error: "Missing ZOOM_SMS_SENDER_USER_ID" }, 500));
      }
      
      const accessToken = await getUserAccessToken(env);
      const result = await sendZoomSmsUserToken({
        accessToken,
        fromE164,
        toE164,
        message,
        senderUserId,
      });

      if (!result.ok) return withCors(req, json({ ok: false, zoom: result }, 502));

      return withCors(req, json({ ok: true, to: toE164, from: fromE164, zoom: result.data }));
    } catch (e) {
      return withCors(req, json({ ok: false, error: e?.message || String(e) }, 500));
    }
  },
};
