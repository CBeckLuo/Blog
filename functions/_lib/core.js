/**
 * Cloudflare Pages Functions 共用工具
 * 鉴权、数据库初始化、统一 JSON 响应
 */
const enc = new TextEncoder();

export function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      ...extra,
    },
  });
}

/* ---------- 建表 & 初始数据（幂等，第一次访问自动执行） ---------- */
export async function ensureSchema(env) {
  if (!env.DB) {
    throw new Error("未找到数据库绑定 DB。请在 Pages 项目 → Settings → Bindings 里添加 D1 数据库，变量名填 DB。");
  }
  await env.DB.batch([
    env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS posts (" +
        "id INTEGER PRIMARY KEY AUTOINCREMENT," +
        "title TEXT NOT NULL," +
        "dek TEXT DEFAULT ''," +
        "cat TEXT DEFAULT '随笔'," +
        "body TEXT DEFAULT ''," +
        "status TEXT DEFAULT 'published'," +
        "created_at TEXT NOT NULL," +
        "updated_at TEXT NOT NULL" +
      ")"
    ),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS media (id TEXT PRIMARY KEY, mime TEXT, data TEXT, created_at TEXT)"),
  ]);

  const cnt = await env.DB.prepare("SELECT COUNT(*) AS n FROM settings").first();
  if (cnt && Number(cnt.n) === 0) {
    const seeds = [
      ["site_name", "副驾位"],
      ["tagline", "一个关于声音、公路和写字的地方。记录车里的音响、路上的歌单，和一些明确「不产出」的下午。"],
      ["about", "这里是关于页。点开后台「站点设置」，把这段换成你自己的介绍。"],
      ["admin_password", "admin123456"],
    ];
    await env.DB.batch(
      seeds.map(([k, v]) =>
        env.DB.prepare("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)").bind(k, v)
      )
    );
  }
}

/* ---------- 设置读写 ---------- */
export async function getSetting(env, key, fallback = "") {
  const row = await env.DB.prepare("SELECT value FROM settings WHERE key = ?").bind(key).first();
  return row ? row.value : fallback;
}

export async function getAdminPassword(env) {
  if (env.ADMIN_PASSWORD) return env.ADMIN_PASSWORD;
  return await getSetting(env, "admin_password", "admin123456");
}

/* ---------- 签名 Cookie ---------- */
function b64url(bytes) {
  let s = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) s += String.fromCharCode(arr[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sign(secret, msg) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return b64url(sig);
}

async function secretOf(env) {
  return env.SESSION_SECRET || ("pw::" + (await getAdminPassword(env)));
}

export async function makeSession(env, days = 7) {
  const exp = Date.now() + days * 24 * 3600 * 1000;
  const secret = await secretOf(env);
  const tok = exp + "." + (await sign(secret, String(exp)));
  return {
    value: tok,
    cookie: "sid=" + tok + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + days * 86400,
  };
}

export function clearCookie() {
  return "sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
}

function readCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  const parts = raw.split(";");
  for (const p of parts) {
    const i = p.indexOf("=");
    if (i > -1 && p.slice(0, i).trim() === name) return p.slice(i + 1).trim();
  }
  return "";
}

export async function isAuthed(request, env) {
  const tok = readCookie(request, "sid");
  if (!tok) return false;
  const dot = tok.indexOf(".");
  if (dot < 1) return false;
  const exp = tok.slice(0, dot);
  const sig = tok.slice(dot + 1);
  if (!/^\d+$/.test(exp) || Number(exp) < Date.now()) return false;
  const secret = await secretOf(env);
  const expect = await sign(secret, exp);
  // 定长比较，避免时序差异
  if (expect.length !== sig.length) return false;
  let diff = 0;
  for (let i = 0; i < expect.length; i++) diff |= expect.charCodeAt(i) ^ sig.charCodeAt(i);
  return diff === 0;
}

export async function requireAuth(request, env) {
  if (await isAuthed(request, env)) return null;
  return json({ error: "未登录或登录已过期" }, 401);
}

/* ---------- 请求体 ---------- */
export async function readBody(request) {
  try {
    const ct = request.headers.get("content-type") || "";
    if (ct.indexOf("application/json") > -1) return await request.json();
    return {};
  } catch (e) {
    return {};
  }
}
