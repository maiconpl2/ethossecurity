# Synthetic fixture for src/ethossecurity/rules/semgrep/python-injection.yaml.
# The snippets imitate typical AI-generated Flask, Django, FastAPI and script code.
# They are never executed.
import ast
import asyncio
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

import asyncpg
import httpx
import jinja2
import pandas as pd
import requests
from clickhouse_driver import Client as ClickHouseClient
from django.core.files.storage import default_storage
from django.db import connection
from django.http import JsonResponse
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.views import View
from fastapi import Depends, FastAPI, File, Request, UploadFile
from fastapi.responses import FileResponse
from flask import Flask, abort, render_template_string, request, send_file, send_from_directory
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup, escape
from pydantic import BaseModel, HttpUrl
from sqlalchemy import text
from werkzeug.utils import secure_filename

app = Flask(__name__)
api = FastAPI()

UPLOAD_DIR = "/srv/uploads"
API_BASE_URL = "https://api.example.com"
ALLOWED_HOSTS = {"images.example.com"}
CLEAR_CMD = "clear"
MAINTENANCE_COMMANDS = {"cache": "redis-cli FLUSHALL", "logs": "logrotate -f /etc/logrotate.conf"}
ALLOWED_REPORTS = {"daily.csv", "weekly.csv"}
USERS_TABLE = "users"
GREETING_TEMPLATE = "<h1>Hello {{ name }}</h1>"
REQUIRED_PACKAGES = ["requests", "python-dotenv"]
ALLOWED_AST_NODES = (ast.Expression, ast.BinOp, ast.UnaryOp, ast.Constant, ast.Add, ast.Sub, ast.Mult, ast.Div)
UPLOAD_PATH = Path(UPLOAD_DIR)
PARTNER_API_URL = "https://partner.example.com/"
DATABASE_URL = "postgresql://localhost/app"


# ----------------------------------------------------------- OS command (scripts)

def backup_database(db_name: str, target_dir: str) -> None:
    # ruleid: ethos.python.os-command-dynamic
    os.system(f"pg_dump {db_name} > {target_dir}/backup.sql")


def disk_usage(path):
    # ruleid: ethos.python.os-command-dynamic
    return subprocess.getoutput("du -sh " + path)


def git_log(repo_path: str) -> str:
    cmd = "git -C %s log --oneline -n 5" % repo_path
    # ruleid: ethos.python.os-command-dynamic
    with os.popen(cmd) as pipe:
        return pipe.read()


def clear_screen() -> None:
    # ok: ethos.python.os-command-dynamic
    os.system("cls" if os.name == "nt" else "clear")


def reset_terminal() -> None:
    # ok: ethos.python.os-command-dynamic
    os.system(CLEAR_CMD)


def convert_video(src: str, dst: str) -> None:
    # ok: ethos.python.os-command-dynamic
    os.system(f"ffmpeg -i {shlex.quote(src)} {shlex.quote(dst)}")


def archive_folder(folder: str, archive_name: str) -> None:
    cmd = f"tar -czf {shlex.quote(archive_name)} {shlex.quote(folder)}"
    # ok: ethos.python.os-command-dynamic
    os.system(cmd)


def install_requirements() -> None:
    # ok: ethos.python.os-command-dynamic
    os.system(f"{sys.executable} -m pip install -r requirements.txt")


def list_directory(path: str) -> str:
    # ok: ethos.python.os-command-dynamic
    return subprocess.run(["ls", "-la", path], capture_output=True, text=True).stdout


async def run_linter(target: str) -> bytes:
    # ruleid: ethos.python.os-command-dynamic
    proc = await asyncio.create_subprocess_shell("ruff check " + target, stdout=asyncio.subprocess.PIPE)
    out, _ = await proc.communicate()
    return out


def install_dependencies() -> None:
    for package in REQUIRED_PACKAGES:
        # ok: ethos.python.os-command-dynamic
        os.system(f"{sys.executable} -m pip install {package}")


# ------------------------------------------------------- OS command (web handlers)

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    # ruleid: ethos.python.os-command-from-request
    output = subprocess.getoutput(f"ping -c 1 {host}")
    return {"output": output}


@api.post("/convert/{filename}")
async def convert(filename: str):
    # ruleid: ethos.python.os-command-from-request
    os.system("convert uploads/" + filename + " out.pdf")
    return {"ok": True}


def run_report(request):
    report = request.GET.get("report")
    # ruleid: ethos.python.os-command-from-request
    os.system(f"python reports/{report}.py")


@app.route("/count-lines")
def count_lines():
    path = request.args.get("path", "")
    # ruleid: ethos.python.os-command-from-request
    total = int(subprocess.getoutput(f"wc -l < {path}"))
    return {"lines": total}


@app.route("/lookup")
def lookup():
    domain = request.args.get("domain", "")
    # ok: ethos.python.os-command-from-request
    result = subprocess.getoutput(f"nslookup {shlex.quote(domain)}")
    return {"result": result}


@app.post("/maintenance")
def maintenance():
    task = request.form.get("task", "")
    command = MAINTENANCE_COMMANDS.get(task)
    if command is None:
        abort(400)
    # ok: ethos.python.os-command-from-request
    os.system(command)
    return {"ok": True}


class PingRequest(BaseModel):
    host: str
    count: int = 1


@api.post("/diagnostics/ping")
async def ping_host(body: PingRequest):
    # ruleid: ethos.python.os-command-from-request
    proc = await asyncio.create_subprocess_shell(f"ping -c {body.count} {body.host}")
    await proc.wait()
    return {"exit_code": proc.returncode}


@app.route("/traceroute")
def traceroute():
    host = request.args.get("host", "")
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        abort(400)
    # ok: ethos.python.os-command-from-request
    return {"output": subprocess.getoutput(f"traceroute -m 10 {host}")}


@app.route("/jobs/<int:job_id>/restart")
def restart_job(job_id):
    # ok: ethos.python.os-command-from-request, ethos.python.os-command-dynamic
    os.system(f"systemctl restart worker@{job_id}")
    return {"ok": True}


# ------------------------------------------------------------ eval / exec (scripts)

def evaluate_formula(formula: str, row: dict) -> float:
    # ruleid: ethos.python.code-eval-dynamic
    return eval(formula, {"__builtins__": {}}, row)


def run_plugin(source_code):
    # ruleid: ethos.python.code-eval-dynamic
    exec(compile(source_code, "<plugin>", "exec"))


def calculate(expression):
    # ruleid: ethos.python.code-eval-dynamic
    return eval(f"({expression}) * 1.0")


def run_user_script(script_path: str) -> dict:
    namespace: dict = {}
    source = Path(script_path).read_text(encoding="utf-8")
    # ruleid: ethos.python.code-eval-dynamic
    code = compile(source, script_path, "exec")
    # ok: ethos.python.code-eval-dynamic
    exec(code, namespace)
    return namespace


def list_functions(source: str):
    # ok: ethos.python.code-eval-dynamic
    tree = compile(source, "<string>", "exec", ast.PyCF_ONLY_AST)
    return [node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]


def score_rules(rules_file: str, context: dict) -> list:
    results = []
    with open("rules.txt", encoding="utf-8") as fh:
        for line in fh:
            # ruleid: ethos.python.code-eval-dynamic
            results.append(eval(line, {}, context))
    return results


def load_settings() -> dict:
    settings: dict = {}
    with open("settings.py", encoding="utf-8") as fh:
        # ok: ethos.python.code-eval-dynamic
        exec(fh.read(), settings)
    return settings


def load_version() -> str:
    namespace: dict = {}
    # ok: ethos.python.code-eval-dynamic
    exec(open("mypackage/_version.py").read(), namespace)
    return namespace["__version__"]


def parse_literal(value: str):
    # ok: ethos.python.code-eval-dynamic
    return ast.literal_eval(value)


def compile_pattern(pattern: str):
    import re

    # ok: ethos.python.code-eval-dynamic
    return re.compile(pattern, re.IGNORECASE)


def safe_calculate(expression: str) -> float:
    tree = ast.parse(expression, mode="eval")
    for node in ast.walk(tree):
        if not isinstance(node, ALLOWED_AST_NODES):
            raise ValueError("unsupported expression")
    # ok: ethos.python.code-eval-dynamic
    return eval(compile(tree, "<expr>", "eval"), {"__builtins__": {}}, {})


def test_money_repr_round_trip():
    amount = Money(10, "BRL")
    # ok: ethos.python.code-eval-dynamic
    assert eval(repr(amount)) == amount


here = os.path.abspath(os.path.dirname(__file__))
about: dict = {}
with open(os.path.join(here, "mypackage", "__version__.py"), encoding="utf-8") as version_file:
    # ok: ethos.python.code-eval-dynamic
    exec(version_file.read(), about)


def prepare_model(model):
    # ok: ethos.python.code-eval-dynamic
    model.eval()
    # ok: ethos.python.code-eval-dynamic
    return eval("{'debug': False}")


# ------------------------------------------------------- eval / exec (web handlers)

@app.post("/calc")
def calc():
    payload = request.get_json()
    # ruleid: ethos.python.code-eval-from-request
    result = eval(payload["expression"])
    return {"result": result}


@api.post("/scripts/run")
async def run_script(req: Request):
    body = await req.json()
    # ruleid: ethos.python.code-eval-from-request
    exec(body["code"], {})
    return {"status": "done"}


class FormulaIn(BaseModel):
    expression: str


@api.post("/formulas/evaluate")
async def evaluate_formula_api(payload: FormulaIn):
    # ruleid: ethos.python.code-eval-from-request
    return {"result": eval(payload.expression, {"__builtins__": {}})}


@app.route("/filters")
def filters_view():
    raw = request.args.get("filters", "{}")
    # ok: ethos.python.code-eval-from-request
    return ast.literal_eval(raw)


@app.route("/power")
def power():
    exponent = request.args.get("exp", 2, type=int)
    # ok: ethos.python.code-eval-from-request
    return {"value": eval(f"2 ** {exponent}")}


# ------------------------------------------------------------------- SQL (helpers)

def find_user(conn: sqlite3.Connection, username: str):
    cur = conn.cursor()
    # ruleid: ethos.python.sql-formatted-query
    cur.execute(f"SELECT id, email FROM users WHERE username = '{username}'")
    return cur.fetchone()


def delete_order(cursor, order_id):
    query = "DELETE FROM orders WHERE id = " + str(order_id)
    # ruleid: ethos.python.sql-formatted-query
    cursor.execute(query)


def search_products(session, term: str):
    # ruleid: ethos.python.sql-formatted-query
    return session.execute(text("SELECT * FROM products WHERE name LIKE '%{}%'".format(term))).all()


def load_sales(engine, region: str) -> pd.DataFrame:
    sql = """
        SELECT region, SUM(total) AS total
        FROM sales
        WHERE region = '%s'
        GROUP BY region
    """ % region
    # ruleid: ethos.python.sql-formatted-query
    return pd.read_sql(sql, engine)


class OrderRepository:
    def by_status(self, status):
        # ruleid: ethos.python.sql-formatted-query
        return Order.objects.raw(f"SELECT * FROM shop_order WHERE status = '{status}'")


def check_login(cursor, username, password):
    query = "SELECT id FROM users WHERE username = '%s' AND password = '%s'"
    # ruleid: ethos.python.sql-formatted-query
    cursor.execute(query % (username, password))
    return cursor.fetchone()


def find_user_safe(conn, username):
    cur = conn.cursor()
    # ok: ethos.python.sql-formatted-query
    cur.execute("SELECT id, email FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def fetch_many(conn, ids):
    placeholders = ", ".join("?" for _ in ids)
    # ok: ethos.python.sql-formatted-query
    return conn.execute(f"SELECT * FROM items WHERE id IN ({placeholders})", ids).fetchall()


def count_users(cursor):
    # ok: ethos.python.sql-formatted-query
    cursor.execute(f"SELECT COUNT(*) FROM {USERS_TABLE}")
    return cursor.fetchone()[0]


def recent_orders(cursor, limit):
    # ok: ethos.python.sql-formatted-query
    cursor.execute(f"SELECT * FROM orders ORDER BY created_at DESC LIMIT {int(limit)}")
    return cursor.fetchall()


def orders_by_customer(engine, table_name, customer_id):
    # ok: ethos.python.sql-formatted-query
    return pd.read_sql(f"SELECT * FROM {table_name} WHERE customer_id = %(cid)s", engine, params={"cid": customer_id})


def table_sizes(conn):
    sizes = {}
    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall():
        # ok: ethos.python.sql-formatted-query
        sizes[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    return sizes


def run_task(executor, task_name):
    # ok: ethos.python.sql-formatted-query
    executor.execute(f"Running task {task_name}")


# -------------------------------------------------------------- SQL (web handlers)

@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    db = sqlite3.connect("app.db")
    # ruleid: ethos.python.sql-query-from-request
    rows = db.execute(f"SELECT id, name FROM users WHERE name LIKE '%{name}%'").fetchall()
    return {"users": rows}


def product_list(request):
    order = request.GET.get("order", "name")
    with connection.cursor() as cursor:
        # ruleid: ethos.python.sql-query-from-request
        cursor.execute("SELECT * FROM shop_product ORDER BY " + order)
        return cursor.fetchall()


@api.get("/reports")
def sales_report(region: str):
    # ruleid: ethos.python.sql-query-from-request
    return pd.read_sql(f"SELECT * FROM sales WHERE region = '{region}'", get_engine()).to_dict()


class CustomerSearchView(View):
    def get(self, *args, **kwargs):
        term = self.request.GET.get("q", "")
        with connection.cursor() as cursor:
            # ruleid: ethos.python.sql-query-from-request
            cursor.execute(f"SELECT id, name FROM crm_customer WHERE name ILIKE '%{term}%'")
            return JsonResponse({"results": cursor.fetchall()})


@app.route("/audit")
def audit_log():
    actor = request.args.get("actor", "")
    # ruleid: ethos.python.sql-query-from-request
    stmt = text(f"SELECT * FROM audit_log WHERE actor = '{actor}'")
    # ok: ethos.python.sql-query-from-request
    rows = db.session.execute(stmt).fetchall()
    return {"rows": [dict(r._mapping) for r in rows]}


@api.get("/items/search")
async def search_items(q: str):
    conn = await asyncpg.connect(DATABASE_URL)
    # ruleid: ethos.python.sql-query-from-request
    return await conn.fetch(f"SELECT id, name FROM items WHERE name ILIKE '%{q}%'")


@app.route("/tickets")
def list_tickets():
    sort = request.args.get("sort", "created_at")
    db = sqlite3.connect("app.db")
    # ruleid: ethos.python.sql-query-from-request
    rows = db.execute(f"SELECT * FROM tickets WHERE owner_id = ? ORDER BY {sort}", (current_user.id,)).fetchall()
    return {"tickets": rows}


@app.route("/analytics/events")
def analytics_events():
    user_id = request.args["user_id"]
    client = ClickHouseClient("localhost")
    # ruleid: ethos.python.sql-query-from-request
    return {"rows": client.execute(f"SELECT * FROM events WHERE user_id = '{user_id}'")}


@app.post("/graphql")
def graphql_endpoint():
    payload = request.get_json()
    # ok: ethos.python.sql-query-from-request
    result = schema.execute(payload["query"])
    return {"data": result.data}


@app.route("/users/<user_id>")
def get_user(user_id):
    db = sqlite3.connect("app.db")
    # ok: ethos.python.sql-query-from-request
    row = db.execute("SELECT id, name FROM users WHERE id = ?", (user_id,)).fetchone()
    return {"user": row}


@app.route("/orders/recent")
def recent_orders_view():
    limit = int(request.args.get("limit", 10))
    db = sqlite3.connect("app.db")
    # ok: ethos.python.sql-query-from-request
    rows = db.execute(f"SELECT * FROM orders ORDER BY id DESC LIMIT {limit}").fetchall()
    return {"orders": rows}


@app.route("/items/bulk", methods=["POST"])
def bulk_insert_items():
    names = request.json["names"]
    db = sqlite3.connect("app.db")
    # ok: ethos.python.sql-query-from-request
    db.executemany(f"INSERT INTO items (name) VALUES ({'?'})", [(n,) for n in names])
    return {"inserted": len(names)}


# ------------------------------------------------------------------ Path traversal

@app.route("/download")
def download():
    filename = request.args.get("file")
    # ruleid: ethos.python.path-traversal-from-request
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/docs/<path:page>")
def docs(page):
    # ruleid: ethos.python.path-traversal-from-request
    with open(f"docs/{page}.md", encoding="utf-8") as fh:
        return fh.read()


@app.post("/upload")
def upload():
    file = request.files["file"]
    # ruleid: ethos.python.path-traversal-from-request
    file.save(os.path.join(UPLOAD_DIR, file.filename))
    return {"ok": True}


@api.get("/notes/{name}")
async def read_note(name: str):
    # ruleid: ethos.python.path-traversal-from-request
    return {"content": (Path("notes") / name).read_text()}


@api.post("/avatar")
async def upload_avatar(file: UploadFile = File(...)):
    dest = Path("avatars") / file.filename
    # ruleid: ethos.python.path-traversal-from-request
    dest.write_bytes(await file.read())
    return {"saved": str(dest)}


@app.route("/attachments/<path:name>")
def attachment(name):
    # ruleid: ethos.python.path-traversal-from-request
    with (UPLOAD_PATH / name).open("rb") as fh:
        return fh.read()


@app.delete("/uploads/<path:name>")
def delete_upload(name):
    # ruleid: ethos.python.path-traversal-from-request
    (UPLOAD_PATH / name).unlink(missing_ok=True)
    return {"deleted": name}


class ExportIn(BaseModel):
    path: str


@api.post("/exports/read")
async def read_export(body: ExportIn):
    # ruleid: ethos.python.path-traversal-from-request
    with open(body.path, encoding="utf-8") as fh:
        return {"content": fh.read()}


def upload_contract(request):
    contract = request.FILES["contract"]
    # ok: ethos.python.path-traversal-from-request
    stored = default_storage.save(f"contracts/{contract.name}", contract)
    return JsonResponse({"path": stored})


@api.get("/me/avatar")
async def my_avatar(username: str = Depends(get_current_username)):
    # ok: ethos.python.path-traversal-from-request
    return FileResponse(os.path.join(UPLOAD_DIR, "avatars", f"{username}.png"))


@app.post("/upload-safe")
def upload_safe():
    file = request.files["file"]
    filename = secure_filename(file.filename)
    # ok: ethos.python.path-traversal-from-request
    file.save(os.path.join(UPLOAD_DIR, filename))
    return {"ok": True}


@app.route("/files/<path:name>")
def serve_file(name):
    # ok: ethos.python.path-traversal-from-request
    return send_from_directory(UPLOAD_DIR, name)


@app.route("/exports")
def export_file():
    name = request.args.get("name", "")
    full_path = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if not full_path.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    # ok: ethos.python.path-traversal-from-request
    return send_file(full_path)


@app.route("/documents/<doc_id>")
def download_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    # ok: ethos.python.path-traversal-from-request
    return send_file(document.storage_path, as_attachment=True)


@app.route("/reports/download")
def download_report():
    report = request.args.get("name", "")
    if report not in ALLOWED_REPORTS:
        abort(404)
    # ok: ethos.python.path-traversal-from-request
    return send_file(os.path.join("reports", report))


@api.get("/thumbs/{name}")
async def thumbnail(name: str):
    # ok: ethos.python.path-traversal-from-request
    return FileResponse(Path("thumbs") / Path(name).name)


# --------------------------------------------------------------------------- SSRF

@app.route("/preview")
def link_preview():
    url = request.args.get("url")
    # ruleid: ethos.python.ssrf-from-request
    resp = requests.get(url, timeout=5)
    return {"status": resp.status_code}


@api.post("/webhooks/test")
async def test_webhook(req: Request):
    data = await req.json()
    async with httpx.AsyncClient() as client:
        # ruleid: ethos.python.ssrf-from-request
        r = await client.post(data["callback_url"], json={"ping": True})
    return {"status": r.status_code}


def fetch_avatar(request):
    avatar_url = request.POST["avatar_url"]
    # ruleid: ethos.python.ssrf-from-request
    with urllib.request.urlopen(avatar_url) as resp:
        return resp.read()


class WebhookIn(BaseModel):
    callback_url: HttpUrl


@api.post("/webhooks/register")
async def register_webhook(body: WebhookIn):
    async with httpx.AsyncClient() as client:
        # ruleid: ethos.python.ssrf-from-request
        await client.post(str(body.callback_url), json={"event": "ping"})
    return {"ok": True}


@app.route("/link-preview")
def link_preview_checked():
    url = request.args.get("url", "")
    if not url.startswith(("http://", "https://")):
        abort(400)
    # ruleid: ethos.python.ssrf-from-request
    return requests.get(url, timeout=5).text


@app.route("/github/<username>")
def github_profile(username):
    # ok: ethos.python.ssrf-from-request
    resp = requests.get(f"https://api.github.com/users/{username}", timeout=5)
    return resp.json()


@app.route("/cities")
def city_info():
    city = request.args.get("city", "")
    # ok: ethos.python.ssrf-from-request
    resp = requests.get(API_BASE_URL + "/cities/" + city, timeout=5)
    return resp.json()


@app.route("/proxy")
def proxy_image():
    target = request.args.get("src", "")
    if urlparse(target).hostname not in ALLOWED_HOSTS:
        abort(400)
    # ok: ethos.python.ssrf-from-request
    return requests.get(target, timeout=5).content


@app.route("/fetch")
def fetch_checked():
    url = request.args.get("url", "")
    if not is_safe_url(url):
        abort(400)
    # ok: ethos.python.ssrf-from-request
    return requests.get(url, timeout=5).text


@app.route("/partner/proxy")
def partner_proxy():
    url = request.args.get("url", "")
    if not url.startswith(PARTNER_API_URL):
        abort(400)
    # ok: ethos.python.ssrf-from-request
    return requests.get(url, timeout=5).content


# ------------------------------------------------- Template injection (helpers)

def render_welcome_email(user_name: str) -> str:
    # ruleid: ethos.python.template-injection-dynamic
    return jinja2.Template(f"<p>Welcome, {user_name}!</p>").render()


def build_page(title, body_html):
    env = jinja2.Environment(autoescape=True)
    source = "<h1>" + title + "</h1>{% block body %}{% endblock %}"
    # ruleid: ethos.python.template-injection-dynamic
    return env.from_string(source).render(body=body_html)


def render_greeting(name):
    # ok: ethos.python.template-injection-dynamic
    return jinja2.Template(GREETING_TEMPLATE).render(name=name)


def render_file_template(path, context):
    template_source = Path(path).read_text(encoding="utf-8")
    # ok: ethos.python.template-injection-dynamic
    return jinja2.Environment(autoescape=True).from_string(template_source).render(**context)


# -------------------------------------------- Template injection (web handlers)

@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    # ruleid: ethos.python.template-injection-from-request
    return render_template_string(f"<h1>Hello {name}!</h1>")


@app.route("/error")
def error_page():
    message = request.values.get("msg", "")
    template = "<div class='error'>%s</div>" % message
    # ruleid: ethos.python.template-injection-from-request
    return render_template_string(template)


@app.route("/hi")
def hi():
    name = request.args.get("name", "guest")
    # ok: ethos.python.template-injection-from-request
    return render_template_string(GREETING_TEMPLATE, name=name)


@app.route("/count")
def count_items():
    n = request.args.get("n", 0, type=int)
    # ok: ethos.python.template-injection-from-request
    return render_template_string(f"<p>{n} items</p>")


@app.post("/emails/preview")
def preview_email_template():
    source = request.form["template"]
    env = SandboxedEnvironment(autoescape=True)
    # ok: ethos.python.template-injection-from-request
    return env.from_string(source).render(name="Ana")


@app.route("/theme")
def theme_color():
    raw = request.args.get("color", "#ffffff")
    # ok: ethos.python.template-injection-from-request
    return {"rgb": Color.from_string(raw).rgb}


# ------------------------------------------------------------ Markup / mark_safe

def highlight(term: str, text_value: str) -> Markup:
    # ruleid: ethos.python.markup-unescaped-dynamic
    return Markup(text_value.replace(term, f"<mark>{term}</mark>"))


def user_badge(user):
    # ruleid: ethos.python.markup-unescaped-dynamic
    return mark_safe(f'<span class="badge">{user.display_name}</span>')


def safe_badge(user):
    # ok: ethos.python.markup-unescaped-dynamic
    return format_html('<span class="badge">{}</span>', user.display_name)


def bold(value):
    # ok: ethos.python.markup-unescaped-dynamic
    return Markup("<b>{}</b>").format(value)


def escaped_note(note):
    # ok: ethos.python.markup-unescaped-dynamic
    return Markup(f"<em>{escape(note)}</em>")
