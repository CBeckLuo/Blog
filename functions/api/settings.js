/**
 * /api/settings
 * GET 读站点设置（公开，只返回前台需要的字段）
 * PUT 修改（需登录）
 */
import { json, ensureSchema, requireAuth, readBody, getSetting } from "../_lib/core.js";

const PUBLIC_KEYS = ["site_name", "tagline", "about", "footer_note"];

export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();

  try {
    await ensureSchema(env);

    if (method === "GET") {
      const out = {};
      for (const k of PUBLIC_KEYS) out[k] = await getSetting(env, k, "");
      return json({ settings: out });
    }

    if (method === "PUT") {
      const guard = await requireAuth(request, env);
      if (guard) return guard;
      const b = await readBody(request);
      const allowed = PUBLIC_KEYS.concat(["admin_password"]);
      const stmts = [];
      for (const k of allowed) {
        if (typeof b[k] === "string" && b[k].length > 0) {
          const v = k === "admin_password" ? b[k].slice(0, 100) : b[k].slice(0, 4000);
          stmts.push(env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)").bind(k, v));
        }
      }
      if (stmts.length) await env.DB.batch(stmts);
      return json({ ok: true });
    }

    return json({ error: "不支持的请求方法" }, 405);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
}
