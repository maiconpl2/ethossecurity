// Synthetic fixtures for src/ethossecurity/rules/semgrep/js-injection.yaml
// (Cloudflare Workers, Hono, Next.js route handlers, Prisma and typed helpers).
import { Hono } from "hono";
import { NextRequest, NextResponse } from "next/server";
import { redirect } from "next/navigation";
import { exec, execSync } from "node:child_process";
import { promisify } from "node:util";
import { readFile, writeFile, unlink } from "node:fs/promises";
import { basename, join } from "node:path";
import { PrismaClient } from "@prisma/client";
import * as vm from "node:vm";

interface Env {
  DB: D1Database;
  AI: Ai;
  VECTORIZE: VectorizeIndex;
}

const prisma = new PrismaClient();
const execAsync = promisify(exec);
const CONTENT_DIR = join(process.cwd(), "content");
const TRUSTED_FEEDS = new Set(["news.example.com", "blog.example.com"]);
const backendUrl = process.env.BACKEND_URL!;

// ---------------------------------------------------------------------------
// Cloudflare Worker (module syntax)
// ---------------------------------------------------------------------------
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const id = url.searchParams.get("id") ?? "";

    // ruleid: ethos.js.sql-injection-from-request
    const note = await env.DB.prepare(`SELECT * FROM notes WHERE id = '${id}'`).first();

    // ok: ethos.js.sql-injection-from-request
    const same = await env.DB.prepare("SELECT * FROM notes WHERE id = ?").bind(id).first();

    const feed = url.searchParams.get("feed");
    if (feed) {
      // ruleid: ethos.js.ssrf-from-request
      const upstream = await fetch(feed, { headers: { accept: "application/rss+xml" } });
      return new Response(upstream.body);
    }

    const next = url.searchParams.get("next") ?? "/";
    if (url.pathname === "/login") {
      // ruleid: ethos.js.open-redirect-from-request
      return Response.redirect(next, 302);
    }

    return Response.json({ note, same });
  },
};

export const originProxy = {
  async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    url.hostname = "origin.example.com";
    // ok: ethos.js.ssrf-from-request
    return fetch(url.toString(), request);
  },
};

export const feedReader = {
  async fetch(request: Request): Promise<Response> {
    const { searchParams } = new URL(request.url);
    const source = new URL(searchParams.get("source") ?? "");
    if (!TRUSTED_FEEDS.has(source.hostname)) {
      return new Response("forbidden", { status: 403 });
    }
    // ok: ethos.js.ssrf-from-request
    return fetch(source);
  },
};

// ---------------------------------------------------------------------------
// Hono on Workers
// ---------------------------------------------------------------------------
const app = new Hono<{ Bindings: Env }>();

app.get("/notes/search", async (c) => {
  const q = c.req.query("q");
  // ruleid: ethos.js.sql-injection-from-request
  const { results } = await c.env.DB.prepare("SELECT * FROM notes WHERE title LIKE '%" + q + "%'").all();
  return c.json(results);
});

app.get("/notes/:id", async (c) => {
  // ok: ethos.js.sql-injection-from-request
  const note = await c.env.DB.prepare("SELECT * FROM notes WHERE id = ?").bind(c.req.param("id")).first();
  return c.json(note);
});

app.post("/tasks/run", async (c) => {
  const body = await c.req.json();
  // ruleid: ethos.js.command-injection-from-request
  const { stdout } = await execAsync(`./scripts/task.sh ${body.task}`);
  return c.text(stdout);
});

app.get("/go", (c) => {
  // ruleid: ethos.js.open-redirect-from-request
  return c.redirect(c.req.query("to") ?? "/");
});

app.get("/docs/:slug", (c) => {
  // ok: ethos.js.open-redirect-from-request
  return c.redirect(`/guides/${c.req.param("slug")}`, 301);
});

const RETURN_PATHS = ["/dashboard", "/billing"];

app.get("/auth/done", (c) => {
  const next = c.req.query("next");
  if (next && RETURN_PATHS.includes(next)) {
    // ok: ethos.js.open-redirect-from-request
    return c.redirect(next);
  }
  return c.redirect("/");
});

app.get("/auth/back", (c) => {
  const back = c.req.query("back");
  if (back && back.length < 200) {
    // ruleid: ethos.js.open-redirect-from-request
    return c.redirect(back);
  }
  return c.redirect("/");
});

const OPERATIONS: Record<string, (a: number, b: number) => number> = {
  add: (a, b) => a + b,
  multiply: (a, b) => a * b,
};

app.post("/calculate", async (c) => {
  const { op, a, b } = await c.req.json();
  const operation = OPERATIONS[String(op)];
  if (!operation) return c.json({ error: "unknown operation" }, 400);
  // ok: ethos.js.code-injection-from-request
  setTimeout(() => console.log("calculated", op), Number(c.req.query("delay") ?? 0));
  return c.json({ result: operation(Number(a), Number(b)) });
});

// Workers AI + Vectorize (official RAG tutorial shape): .query() here is a vector search, not SQL.
app.post("/rag", async (c) => {
  const { question } = await c.req.json();
  const embeddings = await c.env.AI.run("@cf/baai/bge-base-en-v1.5", { text: [question] });
  // ok: ethos.js.sql-injection-from-request
  const matches = await c.env.VECTORIZE.query(embeddings.data[0], { topK: 3 });
  return c.json(matches);
});

app.post("/contacts/sync", async (c) => {
  const { email } = await c.req.json();
  // ok: ethos.js.ssrf-from-request
  const res = await fetch(`${backendUrl}/contacts/${email}`, { method: "POST" });
  return c.json({ ok: res.ok });
});

app.post("/eval", async (c) => {
  const { script } = await c.req.json();
  // ruleid: ethos.js.code-injection-from-request
  const value = vm.runInNewContext(script, {});
  return c.json({ value });
});

// ---------------------------------------------------------------------------
// Next.js route handlers
// ---------------------------------------------------------------------------
export async function GET(request: NextRequest) {
  const file = request.nextUrl.searchParams.get("file") ?? "index.md";
  // ruleid: ethos.js.path-traversal-from-request
  const content = await readFile(`./content/${file}`, "utf8");
  return new Response(content);
}

export async function PUT(request: NextRequest) {
  const name = basename(request.nextUrl.searchParams.get("name") ?? "draft");
  const body = await request.text();
  // ok: ethos.js.path-traversal-from-request
  await writeFile(join(CONTENT_DIR, `${name}.md`), body);
  return NextResponse.json({ saved: name });
}

export async function POST(request: Request) {
  const { webhookUrl, email } = await request.json();

  // ruleid: ethos.js.ssrf-from-request
  await fetch(webhookUrl, { method: "POST", body: JSON.stringify({ event: "signup" }) });

  // ok: ethos.js.sql-injection-from-request
  const users = await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;

  // ruleid: ethos.js.sql-injection-from-request
  const legacy = await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE email = '${email}'`);

  // ok: ethos.js.ssrf-from-request
  await fetch(`${process.env.CRM_API_URL}/contacts?email=${encodeURIComponent(email)}`);

  return NextResponse.json({ users, legacy });
}

export async function DELETE(request: NextRequest) {
  const returnTo = request.nextUrl.searchParams.get("returnTo") ?? "/";
  // ruleid: ethos.js.open-redirect-from-request
  return NextResponse.redirect(new URL(returnTo, request.url));
}

export async function PATCH(request: NextRequest) {
  const tab = request.nextUrl.searchParams.get("tab") ?? "general";
  // ok: ethos.js.open-redirect-from-request
  return NextResponse.redirect(new URL(`/settings/${tab}`, request.url));
}

export async function HEAD(request: NextRequest) {
  const report = request.nextUrl.searchParams.get("report") ?? "";
  const target = join(CONTENT_DIR, report);
  if (!target.startsWith(CONTENT_DIR)) {
    return new Response(null, { status: 403 });
  }
  // ok: ethos.js.path-traversal-from-request
  await readFile(target);
  return new Response(null, { status: 200 });
}

// ---------------------------------------------------------------------------
// Typed helpers (not request handlers)
// ---------------------------------------------------------------------------
export async function getNotesByTag(db: D1Database, tag: string) {
  // ruleid: ethos.js.sql-string-from-function-argument
  return db.prepare(`SELECT * FROM notes WHERE tag = '${tag}'`).all();
}

export async function getNotesPage(db: D1Database, limit: number, offset: number) {
  // ok: ethos.js.sql-string-from-function-argument
  return db.prepare(`SELECT * FROM notes ORDER BY created_at DESC LIMIT ${limit} OFFSET ${offset}`).all();
}

export const deleteNotesByAuthor = async (author: string): Promise<number> => {
  // ruleid: ethos.js.sql-string-from-function-argument
  return prisma.$executeRawUnsafe("DELETE FROM notes WHERE author = '" + author + "'");
};

export async function findNotesByAuthor(author: string) {
  // ok: ethos.js.sql-string-from-function-argument
  return prisma.$queryRaw`SELECT * FROM notes WHERE author = ${author}`;
}

export async function generateThumbnail(inputPath: string, width: number): Promise<void> {
  // ruleid: ethos.js.shell-command-from-function-argument
  await execAsync(`convert "${inputPath}" -resize ${width} thumbnail.png`);
}

export async function listNotesSorted(db: D1Database, sort: "created_at" | "title", ids: number[]) {
  // ok: ethos.js.sql-string-from-function-argument
  return db.prepare(`SELECT * FROM notes WHERE id IN (${ids.join(",")}) ORDER BY ${sort}`).all();
}

export function checkoutRef(ref: string): string {
  if (!/^[\w./-]+$/.test(ref)) throw new Error("invalid ref");
  // ok: ethos.js.shell-command-from-function-argument
  return execSync(`git checkout ${ref}`).toString();
}

export function currentCommit(short: boolean): string {
  // ok: ethos.js.shell-command-from-function-argument
  return execSync(`git rev-parse ${short ? "--short" : ""} HEAD`).toString().trim();
}

export function renderTemplate(template: string, data: Record<string, unknown>): string {
  // ruleid: ethos.js.dynamic-code-evaluation
  const render = new Function("data", "return `" + template + "`;");
  return render(data);
}

export function runUserScript(code: string): unknown {
  // ruleid: ethos.js.dynamic-code-evaluation
  return vm.runInNewContext(code, { Math });
}

export function getGlobal(): typeof globalThis {
  // ok: ethos.js.dynamic-code-evaluation
  return Function("return this")();
}

// ---------------------------------------------------------------------------
// Look-alikes found in real projects (must stay quiet)
// ---------------------------------------------------------------------------
import { collection, getDocs, limit, query as firestoreQuery, where } from "firebase/firestore";
import { and, eq } from "drizzle-orm";
import postgres from "postgres";

export async function listComments(parentCollection: string, parentId: string) {
  // ok: ethos.js.sql-string-from-function-argument
  const snap = await getDocs(firestoreQuery(collection(db, parentCollection, parentId, "comments"), limit(50)));
  return snap.docs;
}

export async function listByTenant(collectionName: string, tenantId: string) {
  // ok: ethos.js.sql-string-from-function-argument
  return getDocs(firestoreQuery(collection(db, collectionName), where("tenantId", "==", tenantId)));
}

export async function restoreBackup(opts: { url: string; file: string }) {
  const sql = postgres(opts.url, { max: 1 });
  for await (const statement of readStatements(opts.file)) {
    // ok: ethos.js.sql-string-from-function-argument
    await sql.unsafe(statement);
  }
}

export async function createSchema(sql: postgres.Sql, schemaName: string) {
  // ok: ethos.js.sql-string-from-function-argument
  await sql.unsafe(`CREATE SCHEMA IF NOT EXISTS ${quoteIdentifier(schemaName)}`);
}

export async function createDatabase(sql: postgres.Sql, databaseName: string) {
  // ruleid: ethos.js.sql-string-from-function-argument
  await sql.unsafe(`CREATE DATABASE "${databaseName}"`);
}

export const workerWithNumberedParams = {
  async fetch(request: Request, env: Env): Promise<Response> {
    const { stage } = await request.json();
    const keys = STAGES.slice(stage);
    const markers = keys.map((_, i) => `?${i + 2}`).join(", ");
    // ok: ethos.js.sql-injection-from-request
    await env.DB.prepare(`UPDATE steps SET undone_at = ?1 WHERE key IN (${markers})`).bind(Date.now(), ...keys).run();
    return new Response(null, { status: 204 });
  },
};

export async function OPTIONS(request: Request) {
  const filter = await request.json();
  // ruleid: ethos.js.nosql-injection-request-object
  const orders = await mongoClient.db().collection("orders").find(filter).toArray();
  return Response.json(orders);
}

app.post("/webhooks/:id/deliver", async (c) => {
  const delivery = await createDelivery(await c.req.json());
  // ok: ethos.js.nosql-injection-request-object
  await drizzleDb.update(deliveries).set({ status: "success" }).where(and(eq(deliveries.id, delivery.id)));
  return c.json({ ok: true });
});

app.get("/dev-proxy", async (c) => {
  const target = new URL(c.req.query("path") ?? "/", "http://localhost:5173/");
  const host = target.hostname;
  if (host !== "localhost" && host !== "127.0.0.1") {
    return c.json({ error: "dev proxy only targets localhost" }, 400);
  }
  // ok: ethos.js.ssrf-from-request
  return fetch(target.href);
});

export async function findActive(collectionName: string) {
  return mongoClient.db().collection(collectionName).find({
    // ok: ethos.js.dynamic-code-evaluation
    $where: () => true,
  });
}

// ---------------------------------------------------------------------------
// Next.js App Router: each block stands for its own route file.
// ---------------------------------------------------------------------------
// app/api/orders/[id]/route.ts: dynamic segment params are request data
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  // ruleid: ethos.js.sql-injection-from-request
  const order = await prisma.$queryRawUnsafe(`SELECT * FROM orders WHERE id = '${id}'`);
  return NextResponse.json(order);
}

// app/api/posts/[slug]/route.ts
export async function DELETE(request: Request, context: { params: { slug: string } }) {
  // ruleid: ethos.js.path-traversal-from-request
  await unlink(join(CONTENT_DIR, `${context.params.slug}.md`));
  return new Response(null, { status: 204 });
}

// app/notes/page.tsx: inline Server Action (a public endpoint)
export async function deleteNoteAction(formData: FormData) {
  "use server";
  const id = formData.get("id");
  // ruleid: ethos.js.sql-injection-from-request
  await prisma.$executeRawUnsafe(`DELETE FROM notes WHERE id = '${id}'`);
  // ok: ethos.js.sql-injection-from-request
  await prisma.$executeRaw`DELETE FROM notes WHERE id = ${id}`;
  // ruleid: ethos.js.open-redirect-from-request
  redirect(String(formData.get("returnTo")));
}
