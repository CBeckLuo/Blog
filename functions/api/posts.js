/**
 * /api/posts
 * GET  列表（?all=1 需登录，取全部含草稿）/ 单篇（?id=12）
 * POST 新建（需登录）
 * PUT  修改（需登录）
 * DELETE 删除（?id=12，需登录）
 */
import { json, ensureSchema, requireAuth, readBody, isAuthed } from "../_lib/core.js";

function clean(v, max) {
  return String(v == null ? "" : v).slice(0, max);
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  try {
    await ensureSchema(env);
    const method = request.method.toUpperCase();

    if (method === "GET") {
      const id = url.searchParams.get("id");
      if (id) {
        const row = await env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(Number(id)).first();
        if (!row) return json({ error: "文章不存在" }, 404);
        if (row.status !== "published" && !(await isAuthed(request, env))) {
          return json({ error: "文章不存在" }, 404);
        }
        return json({ post: row });
      }
      const all = url.searchParams.get("all") === "1";
      if (all) {
        const guard = await requireAuth(request, env);
        if (guard) return guard;
        const rows = await env.DB.prepare(
          "SELECT id, title, dek, cat, status, created_at, updated_at FROM posts ORDER BY created_at DESC"
        ).all();
        return json({ posts: rows.results || [] });
      }
      const rows = await env.DB.prepare(
        "SELECT id, title, dek, cat, created_at FROM posts WHERE status = 'published' ORDER BY created_at DESC"
      ).all();
      return json({ posts: rows.results || [] });
    }

    if (method === "POST") {
      const guard = await requireAuth(request, env);
      if (guard) return guard;
      const b = await readBody(request);
      const title = clean(b.title, 200);
      if (!title) return json({ error: "标题不能为空" }, 400);
      const now = new Date().toISOString();
      const status = b.status === "draft" ? "draft" : "published";
      const res = await env.DB.prepare(
        "INSERT INTO posts (title, dek, cat, body, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(title, clean(b.dek, 300), clean(b.cat, 30) || "随笔", clean(b.body, 200000), status, now, now)
        .run();
      return json({ ok: true, id: res.meta && res.meta.last_row_id });
    }

    if (method === "PUT") {
      const guard = await requireAuth(request, env);
      if (guard) return guard;
      const b = await readBody(request);
      const id = Number(b.id);
      if (!id) return json({ error: "缺少文章 id" }, 400);
      const title = clean(b.title, 200);
      if (!title) return json({ error: "标题不能为空" }, 400);
      await env.DB.prepare(
        "UPDATE posts SET title = ?, dek = ?, cat = ?, body = ?, status = ?, updated_at = ? WHERE id = ?"
      ).bind(title, clean(b.dek, 300), clean(b.cat, 30) || "随笔",
             clean(b.body, 200000), b.status === "draft" ? "draft" : "published",
             new Date().toISOString(), id).run();
      return json({ ok: true });
    }

    if (method === "DELETE") {
      const guard = await requireAuth(request, env);
      if (guard) return guard;
      const id = Number(url.searchParams.get("id"));
      if (!id) return json({ error: "缺少文章 id" }, 400);
      await env.DB.prepare("DELETE FROM posts WHERE id = ?").bind(id).run();
      return json({ ok: true });
    }

    return json({ error: "不支持的请求方法" }, 405);
  } catch (e) {
    return json({ error: String((e && e.message) || e) }, 500);
  }
}
