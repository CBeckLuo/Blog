/**
 * /api/media
 * POST 上传图片（需登录，JSON: { mime, data } data 为 base64，限 1.5MB）
 * GET  ?id=xxx 读取图片
 */
import { json, ensureSchema, requireAuth, readBody } from "../_lib/core.js";

const MAX_BASE64 = 2.1 * 1024 * 1024; // 约 1.5MB 原图

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  try {
    await ensureSchema(env);

    if (method === "POST") {
      const guard = await requireAuth(request, env);
      if (guard) return guard;
      const b = await readBody(request);
      const mime = String(b.mime || "");
      const data = String(b.data || "");
      if (!/^image\/(png|jpeg|jpg|webp|gif|svg\+xml)$/.test(mime)) {
        return json({ error: "只支持 png / jpg / webp / gif / svg 图片" }, 400);
      }
      if (!data || data.length > MAX_BASE64) {
        return json({ error: "图片过大（上限约 1.5MB），请先压缩" }, 413);
      }
      const id = crypto.randomUUID().replace(/-/g, "").slice(0, 20);
      await env.DB.prepare("INSERT INTO media (id, mime, data, created_at) VALUES (?, ?, ?, ?)")
        .bind(id, mime, data, new Date().toISOString()).run();
      return json({ ok: true, url: "/api/media?id=" + id });
    }

    if (method === "GET") {
      const id = url.searchParams.get("id");
      if (!id) return json({ error: "缺少 id" }, 400);
      const row = await env.DB.prepare("SELECT mime, data FROM media WHERE id = ?").bind(id).first();
      if (!row) return new Response("Not found", { status: 404 });
      const bin = Uint8Array.from(atob(row.data), (c) => c.charCodeAt(0));
      return new Response(bin, {
        headers: {
          "content-type": row.mime,
          "cache-control": "public, max-age=31536000, immutable",
          "x-content-type-options": "nosniff",
        },
      });
    }

    return json({ error: "不支持的请求方法" }, 405);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
}
