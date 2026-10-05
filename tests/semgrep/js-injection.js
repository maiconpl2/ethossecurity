// Synthetic fixtures for src/ethossecurity/rules/semgrep/js-injection.yaml (Express / Node style).
const express = require("express");
const { exec, execSync, spawn } = require("child_process");
const { exec: execCallback } = require("child_process");
const util = require("util");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const axios = require("axios");
const mongoose = require("mongoose");
const mysql = require("mysql2/promise");
const { Pool } = require("pg");
const sqlite3 = require("sqlite3");
const { z } = require("zod");

const app = express();
app.use(express.json());

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const execAsync = util.promisify(exec);
const runShell = util.promisify(execCallback);
const todosDb = new sqlite3.Database("./todos.db");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const ALLOWED_HOSTS = ["images.example.com", "cdn.example.com"];
const User = mongoose.model("User", new mongoose.Schema({ email: String, password: String }));
const Session = mongoose.model("Session", new mongoose.Schema({ userId: String }));
const Task = mongoose.model("Task", new mongoose.Schema({ status: String, owner: String }));
const TaskFilter = z.object({ status: z.enum(["open", "done"]), owner: z.string() });

// ---------------------------------------------------------------------------
// Code injection
// ---------------------------------------------------------------------------
app.post("/api/calc", (req, res) => {
  const { expression } = req.body;
  // ruleid: ethos.js.code-injection-from-request
  const result = eval(expression);
  res.json({ result });
});

app.post("/api/sandbox", (req, res) => {
  // ruleid: ethos.js.code-injection-from-request
  const output = vm.runInNewContext(req.body.code, { console });
  res.json({ output });
});

app.post("/api/reports/filter", async (req, res) => {
  // ruleid: ethos.js.code-injection-from-request
  const predicate = new Function("row", "return " + req.body.condition + ";");
  res.json((await loadRows()).filter(predicate));
});

app.get("/api/users/by-prefix", async (req, res) => {
  const users = await User.find({
    // ruleid: ethos.js.code-injection-from-request
    $where: `this.email.startsWith('${req.query.prefix}')`,
  });
  res.json(users);
});

app.get("/api/notify", (req, res) => {
  const delay = Number(req.query.delay) || 1000;
  // ok: ethos.js.code-injection-from-request
  setTimeout(() => notifyChannel(req.query.channel), delay);
  res.sendStatus(202);
});

app.post("/api/import", (req, res) => {
  // ok: ethos.js.code-injection-from-request
  const config = JSON.parse(req.body.config);
  res.json(config);
});

app.get("/api/locale", (req, res) => {
  // ruleid: ethos.js.code-injection-from-request
  const messages = require(`./locales/${req.query.lang}.json`);
  res.json(messages);
});

app.post("/api/calc/safe", (req, res) => {
  const { expression } = req.body;
  if (!/^[0-9+\-*/(). ]+$/.test(expression)) return res.status(400).json({ error: "invalid expression" });
  // ok: ethos.js.code-injection-from-request
  res.json({ result: eval(expression) });
});

function evaluateRule(rule, context) {
  // ruleid: ethos.js.dynamic-code-evaluation
  return new Function("ctx", `with (ctx) { return ${rule.condition}; }`)(context);
}

function loadPlugin(source) {
  // ruleid: ethos.js.dynamic-code-evaluation
  return vm.runInThisContext(source, { filename: "plugin.js" });
}

function legacyPoll(widgetName) {
  // ruleid: ethos.js.dynamic-code-evaluation
  setInterval("refreshWidget('" + widgetName + "')", 5000);
}

function parseLegacyJson(text) {
  // ruleid: ethos.js.dynamic-code-evaluation
  return eval("(" + text + ")");
}

// ok: ethos.js.dynamic-code-evaluation
const globalObject = new Function("return this")();

function scheduleRefresh() {
  // ok: ethos.js.dynamic-code-evaluation
  setTimeout(() => refreshWidget("sales"), 1000);
  // ok: ethos.js.dynamic-code-evaluation
  return eval("2 + 2");
}

async function findOverdrawn() {
  return mongoose.model("Account").find({
    // ok: ethos.js.dynamic-code-evaluation
    $where: function () {
      return this.credits < this.debits;
    },
  });
}

// ---------------------------------------------------------------------------
// OS command injection
// ---------------------------------------------------------------------------
app.post("/api/convert", (req, res) => {
  const { file } = req.body;
  // ruleid: ethos.js.command-injection-from-request
  exec(`ffmpeg -i uploads/${file} -f mp3 converted.mp3`, (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ ok: true });
  });
});

app.get("/api/ping", async (req, res) => {
  // ruleid: ethos.js.command-injection-from-request
  const { stdout } = await execAsync("ping -c 1 " + req.query.host);
  res.send(stdout);
});

app.get("/api/git/log", (req, res) => {
  // ruleid: ethos.js.command-injection-from-request
  const child = spawn("git", ["log", "--oneline", req.query.branch], { shell: true });
  child.stdout.pipe(res);
});

app.get("/api/whois", (req, res) => {
  // ok: ethos.js.command-injection-from-request
  const child = spawn("whois", [req.query.domain]);
  child.stdout.pipe(res);
});

app.get("/api/port-usage", (req, res) => {
  const port = parseInt(req.query.port, 10);
  // ok: ethos.js.command-injection-from-request
  const output = execSync(`lsof -i :${port}`).toString();
  res.send(output);
});

app.post("/api/git/checkout", (req, res) => {
  const { branch } = req.body;
  if (!/^[\w./-]+$/.test(branch)) return res.status(400).json({ error: "invalid branch" });
  // ok: ethos.js.command-injection-from-request
  execSync(`git checkout ${branch}`);
  res.json({ ok: true });
});

app.post("/api/dns", async (req, res) => {
  const { host } = req.body;
  // ruleid: ethos.js.command-injection-from-request
  const { stdout } = await runShell(`nslookup ${host}`);
  res.send(stdout);
});

app.post("/api/archive/extract", (req, res) => {
  // ruleid: ethos.js.command-injection-from-request
  const child = spawn("sh", ["-c", `tar -xzf uploads/${req.body.archive} -C extracted`]);
  child.on("close", (code) => res.json({ code }));
});

app.post("/api/build", (req, res) => {
  // ok: ethos.js.command-injection-from-request
  spawn("sh", ["-c", "npm run build"], { stdio: "inherit" });
  res.status(202).json({ queuedBy: req.body.user });
});

function convertVideo(inputPath, format) {
  // ruleid: ethos.js.shell-command-from-function-argument
  return execSync(`ffmpeg -i "${inputPath}" output.${format}`);
}

async function compressFolder(dir) {
  const archive = path.join(dir, "archive.tar.gz");
  // ruleid: ethos.js.shell-command-from-function-argument
  await execAsync("tar -czf " + archive + " " + dir);
}

function run(command) {
  // ok: ethos.js.shell-command-from-function-argument
  return execSync(command, { stdio: "inherit" });
}

function killPort(port = 3000) {
  // ok: ethos.js.shell-command-from-function-argument
  execSync(`npx kill-port ${port}`);
}

function listFiles(dir) {
  // ok: ethos.js.shell-command-from-function-argument
  return spawn("ls", ["-la", dir]);
}

function runInShell(cmd) {
  return new Promise((resolve, reject) => {
    // ruleid: ethos.js.shell-command-from-function-argument
    exec(`bash -lc "${cmd}"`, (err, stdout) => (err ? reject(err) : resolve(stdout)));
  });
}

function touchUpload(name) {
  name = name.replace(/[^\w.-]/g, "");
  // ok: ethos.js.shell-command-from-function-argument
  execSync(`touch uploads/${name}`);
}

// ---------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------
app.get("/api/users/:id", async (req, res) => {
  // ruleid: ethos.js.sql-injection-from-request
  const { rows } = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows[0]);
});

app.get("/api/products", async (req, res) => {
  const { category, sort } = req.query;
  let sql = "SELECT * FROM products WHERE category = '" + category + "'";
  sql += ` ORDER BY ${sort}`;
  const connection = await mysql.createConnection(process.env.DATABASE_URL);
  // ruleid: ethos.js.sql-injection-from-request
  const [rows] = await connection.execute(sql);
  res.json(rows);
});

app.get("/api/orders/:id", async (req, res) => {
  // ok: ethos.js.sql-injection-from-request
  const { rows } = await pool.query("SELECT * FROM orders WHERE id = $1", [req.params.id]);
  res.json(rows[0]);
});

app.post("/api/orders/bulk", async (req, res) => {
  const { ids } = req.body;
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(", ");
  // ok: ethos.js.sql-injection-from-request
  const { rows } = await pool.query(`SELECT * FROM orders WHERE id IN (${placeholders})`, ids);
  res.json(rows);
});

app.get("/api/orders", async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 20;
  const sortColumn = ["created_at", "total"].includes(req.query.sort) ? req.query.sort : "created_at";
  // ok: ethos.js.sql-injection-from-request
  const { rows } = await pool.query(`SELECT * FROM orders ORDER BY ${sortColumn} LIMIT ${limit}`);
  res.json(rows);
});

// sqlite3: db.all / db.run / db.get
app.get("/api/todos/search", (req, res) => {
  // ruleid: ethos.js.sql-injection-from-request
  todosDb.all(`SELECT * FROM todos WHERE title LIKE '%${req.query.q}%'`, (err, rows) => res.json(rows));
});

app.delete("/api/todos/:id", (req, res) => {
  const query = "DELETE FROM todos WHERE id = " + req.params.id;
  // ruleid: ethos.js.sql-injection-from-request
  todosDb.run(query, (err) => res.sendStatus(err ? 500 : 204));
});

app.get("/api/todos/:id", (req, res) => {
  // ok: ethos.js.sql-injection-from-request
  todosDb.get("SELECT * FROM todos WHERE id = ?", [req.params.id], (err, row) => res.json(row));
});

app.get("/api/inventory", async (req, res) => {
  const sql = mysql.format("SELECT * FROM items WHERE owner = ? AND status = ?", [req.query.owner, req.query.status]);
  const connection = await mysql.createConnection(process.env.DATABASE_URL);
  // ok: ethos.js.sql-injection-from-request
  const [rows] = await connection.query(sql);
  res.json(rows);
});

// Look-alikes that are not SQL: a RAG query engine, a key-value cache, a Firestore field path.
app.post("/api/ask", async (req, res) => {
  // ok: ethos.js.sql-injection-from-request
  const answer = await queryEngine.query(req.body.question);
  res.json({ answer: String(answer) });
});

app.get("/api/cache/:key", async (req, res) => {
  // ok: ethos.js.sql-injection-from-request
  res.json({ value: await cacheDb.get(`cache:${req.params.key}`) });
});

app.get("/api/flags", async (req, res) => {
  // ok: ethos.js.sql-injection-from-request
  const snap = await firestore.collection("users").where(`flags.${req.query.flag}`, "==", true).get();
  res.json({ count: snap.size });
});

async function findUserByEmail(email) {
  // ruleid: ethos.js.sql-string-from-function-argument
  return pool.query(`SELECT * FROM users WHERE email = '${email}'`);
}

class ProductRepository {
  constructor(db) {
    this.db = db;
  }

  async search(term) {
    const sql = "SELECT * FROM products WHERE name LIKE '%" + term + "%'";
    // ruleid: ethos.js.sql-string-from-function-argument
    return this.db.query(sql);
  }

  async findById(id) {
    // ok: ethos.js.sql-string-from-function-argument
    return this.db.query("SELECT * FROM products WHERE id = $1", [id]);
  }
}

async function runQuery(text, params) {
  // ok: ethos.js.sql-string-from-function-argument
  return pool.query(text, params);
}

async function findUsersByIds(ids) {
  const placeholders = ids.map(() => "?").join(", ");
  // ok: ethos.js.sql-string-from-function-argument
  return pool.query(`SELECT * FROM users WHERE id IN (${placeholders})`, ids);
}

async function searchCustomers(name, city) {
  let sql = "SELECT * FROM customers WHERE 1 = 1";
  if (name) sql += " AND name LIKE '%" + name + "%'";
  if (city) sql += ` AND city = '${city}'`;
  // ruleid: ethos.js.sql-string-from-function-argument
  return pool.query(sql);
}

const ALLOWED_COLUMNS = new Set(["name", "email", "phone"]);

async function updateUser(id, fields) {
  const keys = Object.keys(fields).filter((key) => ALLOWED_COLUMNS.has(key));
  const assignments = keys.map((key, i) => `${key} = $${i + 2}`).join(", ");
  // ok: ethos.js.sql-string-from-function-argument
  return pool.query(`UPDATE users SET ${assignments} WHERE id = $1`, [id, ...keys.map((key) => fields[key])]);
}

async function runStatementChunks(statement) {
  let cursor = 0;
  for (const match of statement.matchAll(/;\s*$/gm)) {
    // ok: ethos.js.sql-string-from-function-argument
    await pool.query(statement.slice(cursor, match.index));
    cursor = match.index + match[0].length;
  }
}

// ---------------------------------------------------------------------------
// NoSQL injection
// ---------------------------------------------------------------------------
app.post("/api/login", async (req, res) => {
  // ruleid: ethos.js.nosql-injection-request-object
  const user = await User.findOne(req.body);
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  res.json({ id: user.id });
});

app.get("/api/users", async (req, res) => {
  const { page = 1, ...filters } = req.query;
  // ruleid: ethos.js.nosql-injection-request-object
  const users = await User.find(filters).skip((page - 1) * 20).limit(20);
  res.json(users);
});

app.delete("/api/sessions", async (req, res) => {
  // ruleid: ethos.js.nosql-injection-request-object
  await Session.deleteMany({ ...req.query });
  res.sendStatus(204);
});

app.post("/api/login/safe", async (req, res) => {
  const email = String(req.body.email);
  // ok: ethos.js.nosql-injection-request-object
  const user = await User.findOne({ email });
  res.json({ found: Boolean(user) });
});

app.post("/api/projects", async (req, res) => {
  const project = await projectService.create(req.body);
  if (!project.workspaceId) {
    // ok: ethos.js.nosql-injection-request-object
    await projectService.remove(project.id);
    return res.status(422).json({ error: "invalid workspace" });
  }
  // ok: ethos.js.nosql-injection-request-object
  const owner = await User.findOne({ _id: project.ownerId });
  res.status(201).json({ project, owner: owner.email });
});

app.get("/api/tasks", async (req, res) => {
  const filter = TaskFilter.parse(req.query);
  // ok: ethos.js.nosql-injection-request-object
  res.json(await Task.find(filter));
});

app.get("/api/cart/item", (req, res) => {
  // ok: ethos.js.nosql-injection-request-object
  const item = cartItems.find((entry) => entry.sku === req.query.sku);
  res.json(item);
});

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------
app.get("/api/files/:name", (req, res) => {
  const filePath = path.join(UPLOAD_DIR, req.params.name);
  // ruleid: ethos.js.path-traversal-from-request
  fs.readFile(filePath, "utf8", (err, data) => {
    if (err) return res.status(404).end();
    res.send(data);
  });
});

app.get("/api/reports/download", (req, res) => {
  // ruleid: ethos.js.path-traversal-from-request
  res.download(path.resolve("reports", req.query.file));
});

app.post("/api/notes", (req, res) => {
  // ruleid: ethos.js.path-traversal-from-request
  fs.writeFileSync(`./notes/${req.body.title}.md`, req.body.content);
  res.sendStatus(201);
});

app.get("/api/avatars/:name", (req, res) => {
  const safeName = path.basename(req.params.name);
  // ok: ethos.js.path-traversal-from-request
  fs.createReadStream(path.join(UPLOAD_DIR, safeName)).pipe(res);
});

app.get("/api/i18n", (req, res) => {
  const lang = ["en", "pt"].includes(String(req.query.lang)) ? String(req.query.lang) : "en";
  // ok: ethos.js.path-traversal-from-request
  fs.readFile(path.join(__dirname, "locales", `${lang}.json`), "utf8", (err, text) => res.send(text));
});

app.get("/static/:file", (req, res) => {
  // ok: ethos.js.path-traversal-from-request
  res.sendFile(req.params.file, { root: UPLOAD_DIR });
});

app.get("/api/docs", (req, res) => {
  const target = path.resolve(UPLOAD_DIR, String(req.query.doc));
  if (!target.startsWith(UPLOAD_DIR + path.sep)) return res.status(403).end();
  // ok: ethos.js.path-traversal-from-request
  res.sendFile(target);
});

app.get("/plugins/:id/ui/*", (req, res) => {
  const resolvedFilePath = path.resolve(UPLOAD_DIR, req.params[0]);
  const realFilePath = fs.realpathSync(resolvedFilePath);
  const relative = path.relative(fs.realpathSync(UPLOAD_DIR), realFilePath);
  if (relative.startsWith("..") || path.isAbsolute(relative)) return res.status(403).end();
  // ok: ethos.js.path-traversal-from-request
  res.sendFile(resolvedFilePath, { dotfiles: "allow" });
});

// ---------------------------------------------------------------------------
// SSRF
// ---------------------------------------------------------------------------
app.get("/api/proxy", async (req, res) => {
  // ruleid: ethos.js.ssrf-from-request
  const response = await axios.get(req.query.url);
  res.send(response.data);
});

app.post("/api/webhooks/test", async (req, res) => {
  const { callbackUrl } = req.body;
  // ruleid: ethos.js.ssrf-from-request
  const response = await fetch(callbackUrl, { method: "POST", body: JSON.stringify({ ping: true }) });
  res.json({ status: response.status });
});

app.get("/api/weather", async (req, res) => {
  // ok: ethos.js.ssrf-from-request
  const response = await fetch(`https://api.weather.example.com/v1/forecast?city=${encodeURIComponent(req.query.city)}`);
  res.json(await response.json());
});

app.get("/api/github/:owner", async (req, res) => {
  // ok: ethos.js.ssrf-from-request
  const response = await axios.get(`https://api.github.com/users/${req.params.owner}/repos`);
  res.json(response.data);
});

app.get("/api/image-preview", async (req, res) => {
  const target = new URL(req.query.src);
  if (!ALLOWED_HOSTS.includes(target.hostname)) return res.status(400).end();
  // ok: ethos.js.ssrf-from-request
  const response = await fetch(target);
  res.send(Buffer.from(await response.arrayBuffer()));
});

app.post("/api/contact", async (req, res) => {
  // ok: ethos.js.ssrf-from-request
  await axios.post("https://hooks.example.com/contact", req.body);
  res.sendStatus(202);
});

const internalApiUrl = process.env.INTERNAL_API_URL || "http://localhost:4000";

app.get("/api/internal/users/:id", async (req, res) => {
  // ok: ethos.js.ssrf-from-request
  const response = await fetch(`${internalApiUrl}/users/${req.params.id}`);
  res.json(await response.json());
});

app.get("/api/internal/proxy", async (req, res) => {
  // No "/" after the base: ?path=@evil.example turns the configured host into userinfo.
  // ruleid: ethos.js.ssrf-from-request
  const response = await fetch(`${internalApiUrl}${req.query.path}`);
  res.send(await response.text());
});

app.post("/api/webhooks/ping", async (req, res) => {
  const { webhookUrl } = req.body;
  // ruleid: ethos.js.ssrf-from-request
  await fetch(`${webhookUrl}/ping`, { method: "POST" });
  res.sendStatus(202);
});

app.get("/api/self-check", async (req, res) => {
  // Host-header self calls are deliberately not reported (headers are not SSRF sources).
  // ok: ethos.js.ssrf-from-request
  const response = await fetch(`${req.protocol}://${req.get("host")}/api/health`);
  res.json({ healthy: response.ok });
});

// ---------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------
app.get("/login/callback", (req, res) => {
  // ruleid: ethos.js.open-redirect-from-request
  res.redirect(req.query.returnTo || "/");
});

app.post("/logout", (req, res) => {
  // ruleid: ethos.js.open-redirect-from-request
  res.redirect(302, req.body.next);
});

app.get("/out", (req, res) => {
  res.statusCode = 302;
  // ruleid: ethos.js.open-redirect-from-request
  res.setHeader("Location", req.query.target);
  res.end();
});

app.get("/profile/:id", (req, res) => {
  // ok: ethos.js.open-redirect-from-request
  res.redirect(`/users/${req.params.id}`);
});

app.get("/continue", (req, res) => {
  const next = String(req.query.next || "/");
  if (!next.startsWith("/") || next.startsWith("//")) return res.redirect("/");
  // ok: ethos.js.open-redirect-from-request
  res.redirect(next);
});

app.get("/sso", (req, res) => {
  // ok: ethos.js.open-redirect-from-request
  res.redirect("https://accounts.example.com/login?next=" + encodeURIComponent(req.query.next));
});

const frontendUrl = process.env.FRONTEND_URL;

app.get("/oauth/callback", (req, res) => {
  // ok: ethos.js.open-redirect-from-request
  res.redirect(`${frontendUrl}/auth/complete?code=${req.query.code}`);
});

app.get("/return", (req, res) => {
  const { returnUrl } = req.query;
  // ruleid: ethos.js.open-redirect-from-request
  res.redirect(`${returnUrl}/done`);
});

// req.query values can be arrays, so the startsWith check often follows a typeof guard.
app.get("/after-login", (req, res) => {
  const target = req.query.target;
  if (typeof target === "string" && target.startsWith("/") && !target.startsWith("//")) {
    // ok: ethos.js.open-redirect-from-request
    return res.redirect(target);
  }
  res.redirect("/");
});

app.get("/switch-account", (req, res) => {
  const next = req.query.next;
  if (typeof next !== "string" || !next.startsWith("/") || next.startsWith("//")) return res.redirect("/");
  // ok: ethos.js.open-redirect-from-request
  res.redirect(next);
});

app.get("/goto", (req, res) => {
  const dest = req.query.dest;
  if (typeof dest === "string" && !dest.startsWith("/")) {
    // ruleid: ethos.js.open-redirect-from-request
    return res.redirect(dest);
  }
  res.redirect("/");
});

app.get("/jump", (req, res) => {
  const dest = req.query.dest;
  if (typeof dest === "string" && dest.length > 0) {
    // ruleid: ethos.js.open-redirect-from-request
    return res.redirect(dest);
  }
  res.redirect("/");
});

module.exports = { app, evaluateRule, loadPlugin, legacyPoll, parseLegacyJson, convertVideo, compressFolder, run, runInShell, touchUpload };
