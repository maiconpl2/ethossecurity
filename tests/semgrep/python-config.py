# Synthetic, intentionally insecure fixtures for
# src/ethossecurity/rules/semgrep/python-config.yaml (never executed).
# No value in this file is a real secret.
import base64
import hashlib
import hmac
import os
import pickle
import random
import secrets
import ssl
import string
import tempfile
from hashlib import sha256
from random import choice, randint

import aiohttp
import boto3
import httpx
import jsonpickle
import jwt
import marshal
import redis
import requests
import yaml
from fastapi import FastAPI, File, Request, Response, UploadFile
from flask import Flask, jsonify, make_response, request
from jose import jwt as jose_jwt
from werkzeug.security import generate_password_hash
from werkzeug.serving import run_simple
from yaml import Loader, SafeLoader


# ---------------------------------------------------------------------------
# ethos.python.yaml-unsafe-load
# ---------------------------------------------------------------------------
def load_config(path: str) -> dict:
    with open(path) as fh:
        # ruleid: ethos.python.yaml-unsafe-load
        return yaml.load(fh, Loader=yaml.Loader)


def parse_manifest(text: str) -> dict:
    # ruleid: ethos.python.yaml-unsafe-load
    return yaml.unsafe_load(text)


def import_pipeline():
    # request data: reported once, by ethos.python.yaml-load-from-request
    raw = request.get_data(as_text=True)
    # ruleid: ethos.python.yaml-load-from-request
    data = yaml.unsafe_load(raw)
    # ruleid: ethos.python.yaml-load-from-request
    docs = list(yaml.load_all(raw, Loader))
    # ruleid: ethos.python.yaml-load-from-request
    legacy = yaml.load(raw)
    return data, docs, legacy


@app.route("/pipelines", methods=["POST"])
def create_pipeline():
    # ruleid: ethos.python.yaml-load-from-request
    spec = yaml.load(request.data, Loader=yaml.Loader)
    # ok: ethos.python.yaml-load-from-request
    safe = yaml.safe_load(request.data)
    # ok: ethos.python.yaml-load-from-request
    also_safe = yaml.load(request.data, Loader=yaml.SafeLoader)
    return jsonify({**spec, **safe, **also_safe})


@app.route("/pipelines/upload", methods=["POST"])
def upload_pipeline():
    content = request.files["spec"].read()
    # ruleid: ethos.python.yaml-load-from-request
    return jsonify(list(yaml.unsafe_load_all(content)))


@fastapi_app.post("/pipelines/import")
async def import_pipeline_file(file: UploadFile = File(...)):
    # ruleid: ethos.python.yaml-load-from-request
    return yaml.load(await file.read())


# Typed FastAPI parameters and Flask view arguments are not taint sources of
# yaml-load-from-request, so a route decorator alone must not silence yaml-unsafe-load.
@fastapi_app.post("/pipelines/text")
def import_pipeline_text(spec: str):
    # ruleid: ethos.python.yaml-unsafe-load
    return yaml.load(spec, Loader=yaml.Loader)


@app.route("/pipelines/<path:spec>")
def import_pipeline_path(spec):
    # ruleid: ethos.python.yaml-unsafe-load
    return yaml.unsafe_load(spec)


class PipelineImportView:
    def post(self, *args, **kwargs):
        # ruleid: ethos.python.yaml-load-from-request
        return yaml.load(self.request.body, Loader=yaml.Loader)

    def get(self, request):
        # ruleid: ethos.python.yaml-load-from-request
        return yaml.unsafe_load(request.query_params["spec"])


def load_config_safely(path: str) -> dict:
    with open(path) as fh:
        # ok: ethos.python.yaml-unsafe-load
        cfg = yaml.load(fh, Loader=yaml.SafeLoader)
    with open(path) as fh:
        # ok: ethos.python.yaml-unsafe-load
        other = yaml.safe_load(fh)
    with open(path) as fh:
        # ok: ethos.python.yaml-unsafe-load
        third = yaml.load(fh, Loader=SafeLoader)
    # ok: ethos.python.yaml-unsafe-load
    defaults = yaml.load("retries: 3")
    return {**defaults, **cfg, **other, **third}


def load_with_ruamel(path: str) -> dict:
    from ruamel.yaml import YAML

    yaml = YAML(typ="safe")
    with open(path) as fh:
        # ok: ethos.python.yaml-unsafe-load
        return yaml.load(fh)


# ---------------------------------------------------------------------------
# ethos.python.unsafe-deserialization
# ---------------------------------------------------------------------------
def restore_cart():
    payload = request.cookies.get("cart", "")
    # ruleid: ethos.python.unsafe-deserialization
    cart = jsonpickle.decode(payload)
    return jsonify(cart)


def restore_blob(blob: bytes):
    # ruleid: ethos.python.unsafe-deserialization
    return marshal.loads(blob)


def restore_cart_safely():
    import json

    payload = request.cookies.get("cart", "")
    # ok: ethos.python.unsafe-deserialization
    cart = json.loads(payload)
    # ok: ethos.python.unsafe-deserialization
    encoded = jsonpickle.encode(cart)
    return cart, encoded


def read_local_cache(path: str):
    with open(path, "rb") as fh:
        # ok: ethos.python.unsafe-deserialization
        return marshal.load(fh)


def restore_cart_alias(payload: str):
    # ruleid: ethos.python.unsafe-deserialization
    return jsonpickle.loads(payload)


# ---------------------------------------------------------------------------
# ethos.python.pickle-from-request
# ---------------------------------------------------------------------------
fastapi_app = FastAPI()


def restore_state():
    blob = base64.b64decode(request.cookies.get("state", ""))
    # ruleid: ethos.python.pickle-from-request
    return pickle.loads(blob)


@fastapi_app.post("/import")
async def import_state(file: UploadFile = File(...)):
    content = await file.read()
    # ruleid: ethos.python.pickle-from-request
    return {"items": len(pickle.loads(content))}


@fastapi_app.post("/import-raw")
async def import_raw(req: Request):
    raw = await req.body()
    # ruleid: ethos.python.pickle-from-request
    return pickle.loads(raw)


def load_local_model(path: str):
    with open(path, "rb") as fh:
        # ok: ethos.python.pickle-from-request
        return pickle.load(fh)


def restore_signed_state(signing_key: bytes):
    sig, payload = request.get_data().split(b".", 1)
    expected = hmac.new(signing_key, payload, "sha256").hexdigest().encode()
    if not hmac.compare_digest(sig, expected):
        return None
    # ok: ethos.python.pickle-from-request
    return pickle.loads(payload)


# ---------------------------------------------------------------------------
# ethos.python.tls-verify-disabled
# ---------------------------------------------------------------------------
async def fetch_profile(user_id: str) -> dict:
    # ruleid: ethos.python.tls-verify-disabled
    resp = requests.get(f"https://api.example.com/users/{user_id}", timeout=10, verify=False)
    # ruleid: ethos.python.tls-verify-disabled
    async with httpx.AsyncClient(verify=False) as client:
        other = await client.get("https://api.example.com/health")
    return {"profile": resp.json(), "health": other.status_code}


class PaymentsClient:
    def __init__(self):
        self.session = requests.Session()
        # ruleid: ethos.python.tls-verify-disabled
        self.session.verify = False

    def charge(self, amount: int):
        # ruleid: ethos.python.tls-verify-disabled
        return self.session.post("https://pay.example.com/charge", json={"amount": amount}, verify=False)


def s3_client():
    # ruleid: ethos.python.tls-verify-disabled
    return boto3.client("s3", verify=False)


async def scrape():
    # ruleid: ethos.python.tls-verify-disabled
    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        return await session.get("https://example.com")


def fetch_profile_safely(user_id: str) -> dict:
    # ok: ethos.python.tls-verify-disabled
    resp = requests.get(f"https://api.example.com/users/{user_id}", timeout=10)
    # ok: ethos.python.tls-verify-disabled
    internal = requests.get("https://intranet.local/api", verify="/etc/ssl/internal-ca.pem")
    # ok: ethos.python.tls-verify-disabled
    with httpx.Client(verify=True) as client:
        client.get("https://api.example.com/health")
    verify_tls = os.environ.get("VERIFY_TLS", "1") == "1"
    # ok: ethos.python.tls-verify-disabled
    requests.post("https://api.example.com/x", verify=verify_tls)
    return {"profile": resp.json(), "internal": internal.json()}


async def scrape_per_request(url: str, ca_file: str) -> str:
    async with aiohttp.ClientSession() as session:
        # ruleid: ethos.python.tls-verify-disabled
        async with session.get(url, ssl=False) as resp:
            body = await resp.text()
        # ok: ethos.python.tls-verify-disabled
        async with session.get(url, ssl=ssl.create_default_context(cafile=ca_file)) as resp:
            body += await resp.text()
    return body


def search_client():
    from elasticsearch import Elasticsearch

    # ruleid: ethos.python.tls-verify-disabled
    return Elasticsearch("https://search.internal:9200", verify_certs=False)


def plain_redis():
    # ok: ethos.python.tls-verify-disabled
    return redis.Redis(host="localhost", port=6379, ssl=False)


# ---------------------------------------------------------------------------
# ethos.python.ssl-verification-disabled
# ---------------------------------------------------------------------------
def legacy_https():
    # ruleid: ethos.python.ssl-verification-disabled
    ssl._create_default_https_context = ssl._create_unverified_context
    # ruleid: ethos.python.ssl-verification-disabled
    ctx = ssl._create_unverified_context()
    return ctx


def make_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    # ruleid: ethos.python.ssl-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def make_context_hostname_only():
    ctx = ssl.create_default_context()
    # ruleid: ethos.python.ssl-verification-disabled
    ctx.check_hostname = False
    return ctx


def make_context_from_settings(verify_mode):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # ok: ethos.python.ssl-verification-disabled
    ctx.check_hostname = False
    ctx.verify_mode = verify_mode
    return ctx


def redis_conn():
    # ruleid: ethos.python.ssl-verification-disabled
    return redis.Redis(host="cache.example.com", ssl=True, ssl_cert_reqs="none")


def heroku_redis():
    # ruleid: ethos.python.ssl-verification-disabled
    return redis.from_url(os.environ["REDIS_URL"], ssl_cert_reqs=None)


# Celery settings module.
# ruleid: ethos.python.ssl-verification-disabled
broker_use_ssl = {"ssl_cert_reqs": ssl.CERT_NONE}
# ruleid: ethos.python.ssl-verification-disabled
CELERY_RESULT_BACKEND = "rediss://cache.example.com:6380/0?ssl_cert_reqs=none"
# ok: ethos.python.ssl-verification-disabled
CELERY_BROKER_URL = "rediss://cache.example.com:6380/0?ssl_cert_reqs=required"
# Do not append ?ssl_cert_reqs=none to the URL in production.


def mongo_client():
    from pymongo import MongoClient

    # ruleid: ethos.python.ssl-verification-disabled
    return MongoClient(os.environ["MONGO_URI"], tls=True, tlsAllowInvalidCertificates=True)


def tls_server_context(certfile: str, keyfile: str):
    import socket

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(certfile, keyfile)
    # ok: ethos.python.ssl-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE
    # ok: ethos.python.ssl-verification-disabled
    server = ssl.wrap_socket(socket.socket(), server_side=True, certfile=certfile, cert_reqs=ssl.CERT_NONE)
    return ctx, server


def make_context_safely(cafile: str):
    # ok: ethos.python.ssl-verification-disabled
    ctx = ssl.create_default_context(cafile=cafile)
    # ok: ethos.python.ssl-verification-disabled
    ctx.verify_mode = ssl.CERT_REQUIRED
    # ok: ethos.python.ssl-verification-disabled
    ctx.check_hostname = True
    # ok: ethos.python.ssl-verification-disabled
    if ctx.verify_mode == ssl.CERT_NONE:
        raise RuntimeError("verification must stay on")
    return ctx


# ---------------------------------------------------------------------------
# ethos.python.flask-debug-enabled
# ---------------------------------------------------------------------------
app = Flask(__name__)
api = Flask("api")


def start_dev_server():
    # ruleid: ethos.python.flask-debug-enabled
    run_simple("0.0.0.0", 5000, app, use_reloader=True, use_debugger=True)


def start_api():
    # ruleid: ethos.python.flask-debug-enabled
    api.run(host="0.0.0.0", port=8000, debug=True)


def start_safely():
    import asyncio

    # ok: ethos.python.flask-debug-enabled
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
    # ok: ethos.python.flask-debug-enabled
    asyncio.run(start_api_async(), debug=True)
    # ok: ethos.python.flask-debug-enabled
    app.run(host="127.0.0.1", port=5000)


async def start_api_async():
    return None


def start_with_debug_attribute():
    app.debug = True
    # ruleid: ethos.python.flask-debug-enabled
    app.run(host="0.0.0.0", port=8080)


def start_dashboard():
    import dash

    dash_app = dash.Dash(__name__)
    # ruleid: ethos.python.flask-debug-enabled
    dash_app.run_server(debug=True)


def start_conditionally():
    if os.environ.get("APP_ENV") == "development":
        app.debug = True
    # ok: ethos.python.flask-debug-enabled
    app.run(host="127.0.0.1")


if __name__ == "__main__":
    # ruleid: ethos.python.flask-debug-enabled
    app.run(debug=True)


# ---------------------------------------------------------------------------
# ethos.python.django-debug-true
# ---------------------------------------------------------------------------
# ruleid: ethos.python.django-debug-true
DEBUG = True

ALLOWED_HOSTS = ["*"]
ROOT_URLCONF = "mysite.urls"


class Dev:
    # ruleid: ethos.python.django-debug-true
    DEBUG = True
    INSTALLED_APPS = ["django.contrib.admin", "django.contrib.auth"]


class ScriptOptions:
    # ok: ethos.python.django-debug-true
    DEBUG = True
    VERBOSE = False


class Prod:
    # ok: ethos.python.django-debug-true
    DEBUG = os.environ.get("DJANGO_DEBUG") == "1"
    ALLOWED_HOSTS = ["example.com"]


def configure_logging():
    # ok: ethos.python.django-debug-true
    DEBUG = True
    return DEBUG


if os.environ.get("DJANGO_ENV") == "development":
    # ok: ethos.python.django-debug-true
    DEBUG = True
else:
    # ok: ethos.python.django-debug-true
    DEBUG = False


# ---------------------------------------------------------------------------
# ethos.python.jwt-verification-disabled
# ---------------------------------------------------------------------------
def current_user_id(token: str) -> str:
    # ruleid: ethos.python.jwt-verification-disabled
    claims = jwt.decode(token, options={"verify_signature": False})
    return claims["sub"]


def current_role(token: str) -> str:
    opts = {"verify_signature": False, "verify_exp": True}
    # ruleid: ethos.python.jwt-verification-disabled
    claims = jose_jwt.decode(token, "ignored", options=opts)
    return claims["role"]


def legacy_decode(token: str, key: str) -> dict:
    # ruleid: ethos.python.jwt-verification-disabled
    a = jwt.decode(token, key, verify=False)
    # ruleid: ethos.python.jwt-verification-disabled
    b = jwt.decode(token, key, algorithms=["HS256", "none"])
    return {**a, **b}


def current_user_id_safely(token: str) -> str:
    key = os.environ["JWT_SECRET"]
    # ok: ethos.python.jwt-verification-disabled
    claims = jwt.decode(token, key, algorithms=["HS256"])
    # ok: ethos.python.jwt-verification-disabled
    header = jwt.get_unverified_header(token)
    # ok: ethos.python.jwt-verification-disabled
    more = jwt.decode(token, key, algorithms=["RS256"], options={"verify_signature": True, "require": ["exp"]})
    return claims["sub"] + header["kid"] + more["sub"]


def verify_oidc_token(token: str, jwks_client) -> dict:
    # Peek at the issuer to pick the key set, then verify for real.
    # ok: ethos.python.jwt-verification-disabled
    unverified = jwt.decode(token, options={"verify_signature": False})
    signing_key = jwks_client.get_signing_key_from_jwt(token)
    # ok: ethos.python.jwt-verification-disabled
    return jwt.decode(token, signing_key.key, algorithms=["RS256"], audience="my-api", issuer=unverified["iss"])


def verify_two_step_but_allow_none(token: str, key: str) -> dict:
    # ok: ethos.python.jwt-verification-disabled
    unverified = jwt.decode(token, options={"verify_signature": False})
    # ruleid: ethos.python.jwt-verification-disabled
    return jwt.decode(token, key, algorithms=["none", unverified["alg"]])


# ---------------------------------------------------------------------------
# ethos.python.hardcoded-secret-key
# ---------------------------------------------------------------------------
# ruleid: ethos.python.hardcoded-secret-key
app.secret_key = "super-secret-dev-key-123"
# ruleid: ethos.python.hardcoded-secret-key
app.config["SECRET_KEY"] = "change-me-in-production"
# ruleid: ethos.python.hardcoded-secret-key
app.config.update(DEBUG=False, JWT_SECRET_KEY=b"not-a-real-jwt-key")

# ruleid: ethos.python.hardcoded-secret-key
SECRET_KEY = "django-insecure-placeholder-value-for-tests-only"


class ProductionConfig:
    # ruleid: ethos.python.hardcoded-secret-key
    SECRET_KEY = "prod-key-that-should-not-be-here"


class StagingConfig:
    # ruleid: ethos.python.hardcoded-secret-key
    SECRET_KEY: str = "staging-key-not-real"


class TestingConfig:
    # ok: ethos.python.hardcoded-secret-key
    SECRET_KEY = "testing"


# ok: ethos.python.hardcoded-secret-key
api.secret_key = os.environ["SECRET_KEY"]
# ok: ethos.python.hardcoded-secret-key
api.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "")
# ok: ethos.python.hardcoded-secret-key
api.config["SECRET_KEY"] = secrets.token_hex(32)
# ok: ethos.python.hardcoded-secret-key
api.config["SESSION_COOKIE_NAME"] = "session"

# ruleid: ethos.python.hardcoded-secret-key
JWT_SECRET = "my-jwt-secret-placeholder"


class TestingSettings:
    # ok: ethos.python.hardcoded-secret-key
    SECRET_KEY = "unit-tests-only"


def issue_access_token(user_id: str) -> str:
    # ruleid: ethos.python.hardcoded-secret-key
    return jwt.encode({"sub": user_id}, "placeholder-signing-key", algorithm="HS256")


def read_rs256_token(token: str) -> dict:
    # A public key is not a secret.
    # ok: ethos.python.hardcoded-secret-key
    return jwt.decode(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END PUBLIC KEY-----", algorithms=["RS256"])


def create_app_without_override():
    factory_app = Flask(__name__)
    # ruleid: ethos.python.hardcoded-secret-key
    factory_app.config.from_mapping(SECRET_KEY="dev-placeholder", DATABASE="app.sqlite")
    return factory_app


def create_app_flask_tutorial(test_config=None):
    tutorial_app = Flask(__name__, instance_relative_config=True)
    # ok: ethos.python.hardcoded-secret-key
    tutorial_app.config.from_mapping(SECRET_KEY="dev", DATABASE="app.sqlite")
    if test_config is None:
        tutorial_app.config.from_pyfile("config.py", silent=True)
    else:
        tutorial_app.config.from_mapping(test_config)
    return tutorial_app


# ---------------------------------------------------------------------------
# ethos.python.weak-password-hash
# ---------------------------------------------------------------------------
def register(username: str, password: str) -> dict:
    # ruleid: ethos.python.weak-password-hash
    hashed = hashlib.sha256(password.encode()).hexdigest()
    return {"username": username, "password_hash": hashed}


def check_login(user, form) -> bool:
    salt = user.salt
    # ruleid: ethos.python.weak-password-hash
    digest = hashlib.md5((salt + form["password"]).encode("utf-8")).hexdigest()
    h = hashlib.sha1()
    # ruleid: ethos.python.weak-password-hash
    h.update(form["senha"].encode())
    return digest == user.password_hash and h.hexdigest() == user.legacy_hash


def register_safely(username: str, password: str, reset_token: str) -> dict:
    # ok: ethos.python.weak-password-hash
    hashed = generate_password_hash(password)
    salt = os.urandom(16)
    # ok: ethos.python.weak-password-hash
    derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    # ok: ethos.python.weak-password-hash
    token_digest = hashlib.sha256(reset_token.encode()).hexdigest()
    # ok: ethos.python.weak-password-hash
    etag = hashlib.md5(username.encode()).hexdigest()
    # ok: ethos.python.weak-password-hash
    pwned_prefix = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()[:5]
    return {"hash": hashed, "derived": derived, "token": token_digest, "etag": etag, "hibp": pwned_prefix}


def signup(form: dict, user_pwd: str) -> tuple:
    raw = form["new_password"].encode("utf-8")
    # ruleid: ethos.python.weak-password-hash
    hashed_password = hashlib.sha256(raw).hexdigest()
    # ruleid: ethos.python.weak-password-hash
    legacy = sha256(user_pwd.encode()).hexdigest()
    return hashed_password, legacy


def session_fingerprint(user) -> str:
    # Re-hashing the stored hash so sessions die when the password changes.
    # ok: ethos.python.weak-password-hash
    return hashlib.sha256(user.password_hash.encode()).hexdigest()


def password_strength_demo() -> str:
    # ok: ethos.python.weak-password-hash
    return hashlib.sha256(b"password-strength-demo").hexdigest()


# ---------------------------------------------------------------------------
# ethos.python.insecure-random-secret
# ---------------------------------------------------------------------------
def create_api_key() -> str:
    alphabet = string.ascii_letters + string.digits
    # ruleid: ethos.python.insecure-random-secret
    return "".join(random.choice(alphabet) for _ in range(40))


def send_login_code(user):
    # ruleid: ethos.python.insecure-random-secret
    otp = str(randint(100000, 999999))
    # ruleid: ethos.python.insecure-random-secret
    user.reset_token = "".join(random.choices(string.ascii_letters + string.digits, k=32))
    # ruleid: ethos.python.insecure-random-secret
    temp_password: str = "".join(random.sample(string.ascii_letters, 12))
    return otp, temp_password


def create_api_key_safely() -> str:
    # ok: ethos.python.insecure-random-secret
    return secrets.token_urlsafe(32)


def game_and_sampling(words, vocab_size: int):
    # ok: ethos.python.insecure-random-secret
    secret_number = random.randint(1, 100)
    # ok: ethos.python.insecure-random-secret
    token = choice(words)
    # ok: ethos.python.insecure-random-secret
    max_tokens = random.randint(100, 500)
    # ok: ethos.python.insecure-random-secret
    otp = "".join(secrets.choice(string.digits) for _ in range(6))
    # ok: ethos.python.insecure-random-secret
    delay = random.random() * 2
    return secret_number, token, max_tokens, otp, delay


def sample_next_token(vocab, probs):
    # ok: ethos.python.insecure-random-secret
    next_token = random.choices(vocab, weights=probs, k=1)[0]
    # ok: ethos.python.insecure-random-secret
    return random.choices(vocab, weights=probs)[0] if next_token else None


def mask_tokens(tokens, vocab, tok):
    # ok: ethos.python.insecure-random-secret
    random_token = random.randint(0, len(tokens) - 1)
    # ok: ethos.python.insecure-random-secret
    new_token = vocab[random.randrange(len(vocab))]
    # ok: ethos.python.insecure-random-secret
    masked_token = "[MASK]" if random.random() < 0.15 else tok
    return random_token, new_token, masked_token


def make_temp_password(alphabet: str) -> str:
    # ruleid: ethos.python.insecure-random-secret
    password = "".join(alphabet[random.randint(0, len(alphabet) - 1)] for _ in range(12))
    # ruleid: ethos.python.insecure-random-secret
    pin_code = [alphabet[random.randrange(len(alphabet))] for _ in range(6)]
    return password + "".join(pin_code)


def make_reset_password(alphabet: str) -> str:
    reset_password = ""
    for _ in range(12):
        # ruleid: ethos.python.insecure-random-secret
        reset_password = reset_password + alphabet[random.randrange(len(alphabet))]
    return reset_password


# ---------------------------------------------------------------------------
# ethos.python.tempfile-mktemp
# ---------------------------------------------------------------------------
def export_report(rows) -> str:
    # ruleid: ethos.python.tempfile-mktemp
    path = tempfile.mktemp(suffix=".csv")
    with open(path, "w") as fh:
        fh.write("\n".join(rows))
    return path


def export_upload(data: bytes) -> str:
    # ruleid: ethos.python.tempfile-mktemp
    target = tempfile.mktemp(prefix="upload-", dir="/tmp")
    with open(target, "wb") as fh:
        fh.write(data)
    return target


def export_report_safely(rows) -> str:
    # ok: ethos.python.tempfile-mktemp
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(rows))
    # ok: ethos.python.tempfile-mktemp
    with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
        tmp.write("x")
    return path


# ---------------------------------------------------------------------------
# ethos.python.insecure-auth-cookie
# ---------------------------------------------------------------------------
@app.post("/login")
def login():
    token = create_api_key_safely()
    resp = make_response(jsonify({"ok": True}))
    # ruleid: ethos.python.insecure-auth-cookie
    resp.set_cookie("session_token", token, max_age=3600)
    # ruleid: ethos.python.insecure-auth-cookie
    resp.set_cookie(key="refresh_token", value=token, httponly=True)
    # ruleid: ethos.python.insecure-auth-cookie
    resp.set_cookie("auth", token, secure=True, httponly=False)
    return resp


@app.post("/login-safe")
def login_safely():
    token = create_api_key_safely()
    resp = make_response(jsonify({"ok": True}))
    # ok: ethos.python.insecure-auth-cookie
    resp.set_cookie("session_token", token, secure=True, httponly=True, samesite="Lax")
    # ok: ethos.python.insecure-auth-cookie
    resp.set_cookie("theme", "dark")
    # ok: ethos.python.insecure-auth-cookie
    resp.set_cookie("csrf_token", secrets.token_hex(16), secure=True, samesite="Strict")
    cookie_opts = {"secure": True, "httponly": True, "samesite": "Lax"}
    # ok: ethos.python.insecure-auth-cookie
    resp.set_cookie("access_token", token, **cookie_opts)
    # ok: ethos.python.insecure-auth-cookie
    resp.set_cookie("session", token, secure=not app.debug, httponly=True)
    return resp


@fastapi_app.post("/token")
async def issue_cookie(response: Response):
    token = create_api_key_safely()
    # ruleid: ethos.python.insecure-auth-cookie
    response.set_cookie(key="access_token", value=f"Bearer {token}", httponly=True)
    return {"ok": True}


@app.post("/logout")
def logout():
    resp = make_response(jsonify({"ok": True}))
    # ok: ethos.python.insecure-auth-cookie
    resp.set_cookie("session_token", "", expires=0)
    # ok: ethos.python.insecure-auth-cookie
    resp.set_cookie("remember_me", "0", max_age=60)
    return resp
