/**
 * /api/login
 * GET    查询当前登录状态
 * POST   登录 { password }
 * DELETE 退出登录
 */
import { json, ensureSchema, getAdminPassword, makeSession, clearCookie, isAuthed, readBody } from "../_lib/core.js";

export async function onRequest(context) {
  const { request, env } = context;
  const method = request.method.toUpperCase();

  try {
    await ensureSchema(env);

    if (method === "GET") {
      return json({ authed: await isAuthed(request, env) });
    }

    if (method === "POST") {
      const b = await readBody(request);
      const pass = String(b.password || "");
      const real = await getAdminPassword(env);
      if (!pass || pass !== real) {
        return json({ error: "密码不正确" }, 401);
      }
      const s = await makeSession(env, 7);
      return json({ ok: true }, 200, { "set-cookie": s.cookie });
    }

    if (method === "DELETE") {
      return json({ ok: true }, 200, { "set-cookie": clearCookie() });
    }

    return json({ error: "不支持的请求方法" }, 405);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
}
