// Fixture for src/ethossecurity/rules/semgrep/js-web.yaml (server code: Express, Hono, Cloudflare Workers, Next.js).
import crypto from "crypto";
import https from "https";
import express, { NextFunction, Request, Response } from "express";
import cors from "cors";
import session from "express-session";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { Pool } from "pg";
import { jwtVerify, decodeJwt, SignJWT } from "jose";
import { cookies } from "next/headers";
import { NextRequest, NextResponse } from "next/server";
import { cors as honoCors } from "hono/cors";
import { expressjwt } from "express-jwt";
import http from "http";
import config from "config";
import CryptoJS from "crypto-js";
import escapeHtml from "escape-html";
import Koa from "koa";
import md5 from "md5";
import mongoose from "mongoose";
import { Hono } from "hono";
import { setCookie } from "hono/cookie";
import koaJwt from "koa-jwt";
import { readFileSync } from "fs";

const app = express();
const hono = new Hono();
const koa = new Koa();
const ALLOWED_ORIGINS = ["https://app.example.com", "https://admin.example.com"];

// ---------------------------------------------------------------------------
// ethos.js.cors-reflected-origin-credentials
// ---------------------------------------------------------------------------
app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  // ruleid: ethos.js.cors-reflected-origin-credentials
  res.setHeader("Access-Control-Allow-Origin", origin as string);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

app.use((req: Request, res: Response, next: NextFunction) => {
  res.header("Access-Control-Allow-Credentials", "true");
  // ruleid: ethos.js.cors-reflected-origin-credentials
  res.header("access-control-allow-origin", req.header("Origin"));
  next();
});

app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin ?? "";
  if (ALLOWED_ORIGINS.includes(origin)) {
    // ok: ethos.js.cors-reflected-origin-credentials
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});

app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED_ORIGINS.indexOf(origin) !== -1) {
    // ok: ethos.js.cors-reflected-origin-credentials
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Credentials", "true");
  }
  next();
});

app.use((req: Request, res: Response, next: NextFunction) => {
  // Public API without credentials: echoing the origin is equivalent to "*".
  // ok: ethos.js.cors-reflected-origin-credentials
  res.setHeader("Access-Control-Allow-Origin", req.headers.origin || "*");
  next();
});

export const worker = {
  async fetch(request: Request & { headers: Headers }): Promise<Response> {
    const origin = request.headers.get("Origin") ?? "*";
    return new Response("ok", {
      headers: {
        // ruleid: ethos.js.cors-reflected-origin-credentials
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
      },
    });
  },
};

export async function corsPreflight(request: Request & { headers: Headers }): Promise<Response> {
  const origin = request.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return new Response(null, {
    headers: {
      // ok: ethos.js.cors-reflected-origin-credentials
      "Access-Control-Allow-Origin": allowed,
      "Access-Control-Allow-Credentials": "true",
    },
  });
}

// A method check is not an origin check.
app.use((req: Request, res: Response, next: NextFunction) => {
  if (req.method === "OPTIONS") {
    // ruleid: ethos.js.cors-reflected-origin-credentials
    res.header("Access-Control-Allow-Origin", req.headers.origin as string);
    res.header("Access-Control-Allow-Credentials", "true");
    return res.sendStatus(204);
  }
  next();
});

koa.use(async (ctx, next) => {
  ctx.set("Access-Control-Allow-Credentials", "true");
  // ruleid: ethos.js.cors-reflected-origin-credentials
  ctx.set("Access-Control-Allow-Origin", ctx.get("Origin"));
  await next();
});

export async function OPTIONS(request: NextRequest) {
  const origin = request.headers.get("origin") ?? "";
  return new NextResponse(null, {
    headers: {
      "Access-Control-Allow-Credentials": "true",
      // ruleid: ethos.js.cors-reflected-origin-credentials
      "Access-Control-Allow-Origin": origin,
    },
  });
}

// Early return guarded by a short-circuit allowlist check.
app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  if (!origin || !ALLOWED_ORIGINS.includes(origin as string)) {
    return res.status(403).end();
  }
  // ok: ethos.js.cors-reflected-origin-credentials
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

app.use((req: Request, res: Response, next: NextFunction) => {
  const origin = req.headers.origin;
  switch (origin) {
    case "https://app.example.com":
    case "https://admin.example.com":
      // ok: ethos.js.cors-reflected-origin-credentials
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Credentials", "true");
      break;
    default:
      break;
  }
  next();
});

app.use((req: Request, res: Response, next: NextFunction) => {
  // Read from configuration, not from the request.
  const origin = config.get("origin") as string;
  // ok: ethos.js.cors-reflected-origin-credentials
  res.setHeader("Access-Control-Allow-Origin", origin);
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

// ---------------------------------------------------------------------------
// ethos.js.cors-permissive-origin-credentials
// ---------------------------------------------------------------------------
// ruleid: ethos.js.cors-permissive-origin-credentials
app.use(cors({ origin: true, credentials: true }));

app.use(
  // ruleid: ethos.js.cors-permissive-origin-credentials
  cors({ credentials: true, origin: (origin, callback) => callback(null, true), methods: ["GET", "POST"] }),
);

// ruleid: ethos.js.cors-permissive-origin-credentials
export const honoMiddleware = honoCors({ origin: (origin) => origin, credentials: true });

// ok: ethos.js.cors-permissive-origin-credentials
app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));

// ok: ethos.js.cors-permissive-origin-credentials
app.use(cors({ origin: true }));

app.use(
  cors({
    // ok: ethos.js.cors-permissive-origin-credentials
    origin: (origin, callback) => {
      if (!origin || ALLOWED_ORIGINS.includes(origin)) return callback(null, true);
      callback(new Error("Not allowed by CORS"));
    },
    credentials: true,
  }),
);

// ---------------------------------------------------------------------------
// ethos.js.cors-wildcard-origin-credentials
// ---------------------------------------------------------------------------
// ruleid: ethos.js.cors-wildcard-origin-credentials
app.use(cors({ origin: "*", credentials: true }));

app.use((req: Request, res: Response, next: NextFunction) => {
  // ruleid: ethos.js.cors-wildcard-origin-credentials
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Credentials", "true");
  next();
});

export const wildcardHeaders = {
  // ruleid: ethos.js.cors-wildcard-origin-credentials
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Credentials": "true",
};

// ok: ethos.js.cors-wildcard-origin-credentials
app.use(cors({ origin: "*" }));

app.use((req: Request, res: Response, next: NextFunction) => {
  // ok: ethos.js.cors-wildcard-origin-credentials
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Content-Type", "application/json");
  next();
});

// ok: ethos.js.cors-wildcard-origin-credentials
export const publicHeaders = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };

// ---------------------------------------------------------------------------
// ethos.js.tls-verification-disabled
// ---------------------------------------------------------------------------
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ruleid: ethos.js.tls-verification-disabled
  ssl: { rejectUnauthorized: false },
});

export const insecureAgent = new https.Agent({
  keepAlive: true,
  // ruleid: ethos.js.tls-verification-disabled
  rejectUnauthorized: false,
});

// ruleid: ethos.js.tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

export const securePool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // ok: ethos.js.tls-verification-disabled
  ssl: { rejectUnauthorized: true, ca: process.env.DB_CA_CERT },
});

export const envAgent = new https.Agent({
  // ok: ethos.js.tls-verification-disabled
  rejectUnauthorized: process.env.NODE_ENV === "production",
});

// ok: ethos.js.tls-verification-disabled
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";

mongoose.connect(process.env.MONGODB_URI as string, {
  // ruleid: ethos.js.tls-verification-disabled
  tlsAllowInvalidCertificates: true,
});

mongoose.connect(process.env.MONGODB_URI as string, {
  // ok: ethos.js.tls-verification-disabled
  tlsAllowInvalidCertificates: false,
  tlsCAFile: process.env.MONGODB_CA_FILE,
});

// ---------------------------------------------------------------------------
// ethos.js.insecure-random-secret
// ---------------------------------------------------------------------------
export function createPasswordReset(user: { resetToken?: string; sessionId?: string }) {
  // ruleid: ethos.js.insecure-random-secret
  const resetToken = Math.random().toString(36).substring(2);
  // ruleid: ethos.js.insecure-random-secret
  user.sessionId = Math.random().toString(36).slice(2);
  // ok: ethos.js.insecure-random-secret
  const safeToken = crypto.randomBytes(32).toString("hex");
  // ok: ethos.js.insecure-random-secret
  const retryDelayMs = Math.random() * 1000;
  return { resetToken, safeToken, retryDelayMs };
}

export function generateOtp(): string {
  // ruleid: ethos.js.insecure-random-secret
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export function sendVerificationEmail(email: string) {
  // ruleid: ethos.js.insecure-random-secret
  const code = Math.floor(100000 + Math.random() * 900000);
  // ruleid: ethos.js.insecure-random-secret
  const apiClient = { email, apiKey: "sk_" + Math.random().toString(36).slice(2) };
  // ok: ethos.js.insecure-random-secret
  const requestId = Math.random().toString(36).slice(2, 10);
  const order = { sku: "A1", code: "" };
  // ok: ethos.js.insecure-random-secret
  order.code = Math.random().toString(36).slice(2, 8).toUpperCase();
  return { code, apiClient, requestId, order };
}

export class ApiKeyService {
  // ruleid: ethos.js.insecure-random-secret
  private apiKey = "sk_" + Math.random().toString(36).slice(2);
}

// ruleid: ethos.js.insecure-random-secret
export const generateVerificationCode = (): string => Math.floor(100000 + Math.random() * 900000).toString();

export function createShortCode(): string {
  // URL shortener slugs are public identifiers.
  // ok: ethos.js.insecure-random-secret
  return Math.random().toString(36).slice(2, 8);
}

// ---------------------------------------------------------------------------
// ethos.js.weak-password-hash
// ---------------------------------------------------------------------------
export function hashPasswordSha256(password: string): string {
  // ruleid: ethos.js.weak-password-hash
  return crypto.createHash("sha256").update(password).digest("hex");
}

app.post("/register", async (req: Request, res: Response) => {
  const hash = crypto.createHash("md5");
  // ruleid: ethos.js.weak-password-hash
  hash.update(req.body.password);
  // ok: ethos.js.weak-password-hash
  const passwordHash = await bcrypt.hash(req.body.password, 12);
  res.json({ md5: hash.digest("hex"), passwordHash });
});

export async function hashPasswordInWorker(password: string, salt: string): Promise<string> {
  const data = new TextEncoder().encode(password + salt);
  // ruleid: ethos.js.weak-password-hash
  const digest = await crypto.subtle.digest("SHA-256", data);
  return btoa(String.fromCharCode(...new Uint8Array(digest)));
}

export function hashResetToken(resetToken: string, fileBuffer: Buffer) {
  // ok: ethos.js.weak-password-hash
  const tokenHash = crypto.createHash("sha256").update(resetToken).digest("hex");
  // ok: ethos.js.weak-password-hash
  const etag = crypto.createHash("sha1").update(fileBuffer).digest("hex");
  return { tokenHash, etag };
}

export async function bodyDigest(body: string) {
  // ok: ethos.js.weak-password-hash
  return crypto.subtle.digest("SHA-256", new TextEncoder().encode(body));
}

app.post("/signup", async (req: Request, res: Response) => {
  const { password, newPassword } = req.body;
  // ruleid: ethos.js.weak-password-hash
  const legacy = md5(password);
  // ruleid: ethos.js.weak-password-hash
  const hashed = CryptoJS.SHA256(newPassword).toString();
  res.json({ legacy, hashed });
});

// Have I Been Pwned range check: the uppercase SHA-1 prefix is sent, nothing is stored.
export async function isPasswordPwned(password: string): Promise<boolean> {
  // ok: ethos.js.weak-password-hash
  const sha1 = crypto.createHash("sha1").update(password).digest("hex").toUpperCase();
  const res = await fetch(`https://api.pwnedpasswords.com/range/${sha1.slice(0, 5)}`);
  return (await res.text()).includes(sha1.slice(5));
}

// Equal-length constant-time comparison of a configured secret.
export function checkAdminPassword(password: string): boolean {
  // ok: ethos.js.weak-password-hash
  const given = crypto.createHash("sha256").update(password).digest();
  // ok: ethos.js.weak-password-hash
  const expected = crypto.createHash("sha256").update(process.env.ADMIN_PASSWORD ?? "").digest();
  return crypto.timingSafeEqual(given, expected);
}

export function sessionEtag(user: { id: string; passwordUpdatedAt: Date }) {
  // ok: ethos.js.weak-password-hash
  return crypto.createHash("md5").update(`${user.id}:${user.passwordUpdatedAt.getTime()}`).digest("hex");
}

// ---------------------------------------------------------------------------
// ethos.js.jwt-none-algorithm
// ---------------------------------------------------------------------------
export function verifyAccessToken(token: string) {
  // ruleid: ethos.js.jwt-none-algorithm
  return jwt.verify(token, process.env.JWT_SECRET as string, { algorithms: ["HS256", "none"] });
}

// ruleid: ethos.js.jwt-none-algorithm
app.use(expressjwt({ secret: process.env.JWT_SECRET as string, algorithms: ["none"] }));

export function verifyStrict(token: string) {
  // ok: ethos.js.jwt-none-algorithm
  return jwt.verify(token, process.env.JWT_SECRET as string, { algorithms: ["HS256"] });
}

export async function verifyWithJose(token: string, key: Uint8Array) {
  // ok: ethos.js.jwt-none-algorithm
  return jwtVerify(token, key, { algorithms: ["RS256"] });
}

// ---------------------------------------------------------------------------
// ethos.js.jwt-decode-without-verify
// ---------------------------------------------------------------------------
export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.split(" ")[1] ?? "";
  // ruleid: ethos.js.jwt-decode-without-verify
  const user = jwt.decode(token);
  (req as any).user = user;
  next();
}

app.get("/admin", (req: Request, res: Response) => {
  // ruleid: ethos.js.jwt-decode-without-verify
  const claims = jwt.decode(req.cookies.token) as { role?: string } | null;
  if (claims?.role !== "admin") return res.status(403).end();
  res.send("welcome");
});

export function middleware(request: NextRequest) {
  const token = request.cookies.get("session")?.value ?? "";
  // ruleid: ethos.js.jwt-decode-without-verify
  const payload = decodeJwt(token);
  if (payload.role !== "admin") return NextResponse.redirect(new URL("/login", request.url));
  return NextResponse.next();
}

export function requireAuthVerified(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.split(" ")[1] ?? "";
  // ok: ethos.js.jwt-decode-without-verify
  const header = jwt.decode(token, { complete: true });
  try {
    (req as any).user = jwt.verify(token, process.env.JWT_SECRET as string, { algorithms: ["HS256"] });
    (req as any).kid = header?.header.kid;
    next();
  } catch {
    res.status(401).end();
  }
}

export function readClaimsForUi(token: string) {
  // ok: ethos.js.jwt-decode-without-verify
  return jwt.decode(token);
}

// Next.js App Router route handler and Hono handler that only decode.
export async function GET(request: NextRequest) {
  const token = request.headers.get("authorization")?.replace("Bearer ", "") ?? "";
  // ruleid: ethos.js.jwt-decode-without-verify
  const { role } = decodeJwt(token) as { role?: string };
  return NextResponse.json({ isAdmin: role === "admin" });
}

hono.get("/admin", async (c) => {
  // ruleid: ethos.js.jwt-decode-without-verify
  const payload = jwt.decode(c.req.header("Authorization")!.slice(7)) as { role?: string } | null;
  return c.json({ isAdmin: payload?.role === "admin" });
});

// The route is protected by middleware that verifies the token.
app.get("/me", requireAuthVerified, (req: Request, res: Response) => {
  // ok: ethos.js.jwt-decode-without-verify
  res.json(jwt.decode(req.headers.authorization!.split(" ")[1]));
});

async function verifyJwt(token: string) {
  return jwt.verify(token, process.env.JWT_SECRET as string, { algorithms: ["HS256"] });
}

app.get("/profile", async (req: Request, res: Response) => {
  const token = req.cookies.token;
  await verifyJwt(token);
  // ok: ethos.js.jwt-decode-without-verify
  const { sub } = jwt.decode(token) as { sub: string };
  res.json({ sub });
});

// ---------------------------------------------------------------------------
// ethos.js.hardcoded-jwt-secret
// ---------------------------------------------------------------------------
export function issueSessionToken(userId: string) {
  // ruleid: ethos.js.hardcoded-jwt-secret
  return jwt.sign({ sub: userId }, "dev-secret", { expiresIn: "1h" });
}

export function readSessionToken(token: string) {
  // ruleid: ethos.js.hardcoded-jwt-secret
  return jwt.verify(token, 'super-secret-key', { algorithms: ["HS256"] });
}

export function issueRefreshToken(userId: string) {
  // ruleid: ethos.js.hardcoded-jwt-secret
  return jwt.sign({ sub: userId }, Buffer.from("refresh-secret", "utf-8"));
}

export async function issueEdgeToken(userId: string) {
  return new SignJWT({ sub: userId })
    .setProtectedHeader({ alg: "HS256" })
    .setExpirationTime("2h")
    // ruleid: ethos.js.hardcoded-jwt-secret
    .sign(new TextEncoder().encode("my-jose-secret"));
}

export async function readEdgeToken(token: string) {
  // ruleid: ethos.js.hardcoded-jwt-secret
  return jwtVerify(token, new TextEncoder().encode("my-jose-secret"), { algorithms: ["HS256"] });
}

// ruleid: ethos.js.hardcoded-jwt-secret
app.use("/api", expressjwt({ secret: "shhhhh", algorithms: ["HS256"] }));

// ruleid: ethos.js.hardcoded-jwt-secret
koa.use(koaJwt({ secret: "koa-shared-secret" }));

export function issueFromEnv(userId: string) {
  // ok: ethos.js.hardcoded-jwt-secret
  return jwt.sign({ sub: userId }, process.env.JWT_SECRET as string, { expiresIn: "1h" });
}

export function issueWithKeyFile(userId: string) {
  // ok: ethos.js.hardcoded-jwt-secret
  return jwt.sign({ sub: userId }, readFileSync("keys/private.pem"), { algorithm: "RS256" });
}

export function verifyWithPublicKey(token: string) {
  // ok: ethos.js.hardcoded-jwt-secret
  return jwt.verify(token, "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1L\n-----END PUBLIC KEY-----", { algorithms: ["RS256"] });
}

export async function readEdgeTokenFromEnv(token: string, secret: Uint8Array) {
  // ok: ethos.js.hardcoded-jwt-secret
  await jwtVerify(token, new TextEncoder().encode(process.env.JWT_SECRET), { algorithms: ["HS256"] });
  // ok: ethos.js.hardcoded-jwt-secret
  return jwtVerify(token, secret, { algorithms: ["HS256"] });
}

export function issueWithConfiguredSecret(userId: string, jwtSecret: string) {
  // ok: ethos.js.hardcoded-jwt-secret
  return jwt.sign({ sub: userId }, jwtSecret);
}

// ok: ethos.js.hardcoded-jwt-secret
app.use(expressjwt({ secret: config.get("jwtSecret"), algorithms: ["HS256"] }));

// ---------------------------------------------------------------------------
// ethos.js.auth-cookie-without-httponly
// ---------------------------------------------------------------------------
app.post("/login", (req: Request, res: Response) => {
  const token = jwt.sign({ sub: req.body.email }, process.env.JWT_SECRET as string);
  // ruleid: ethos.js.auth-cookie-without-httponly
  res.cookie("token", token, { httpOnly: false, secure: true, sameSite: "lax" });
  // ruleid: ethos.js.auth-cookie-without-httponly
  res.cookie("session", req.body.sessionId);
  // ruleid: ethos.js.auth-cookie-without-httponly
  res.cookie("auth_token", token, { maxAge: 24 * 60 * 60 * 1000 });
  // ok: ethos.js.auth-cookie-without-httponly
  res.cookie("token", token, { httpOnly: true, secure: true, sameSite: "strict" });
  // ok: ethos.js.auth-cookie-without-httponly
  res.cookie("XSRF-TOKEN", req.body.csrf, { httpOnly: false });
  // ok: ethos.js.auth-cookie-without-httponly
  res.cookie("theme", "dark");
  // ok: ethos.js.auth-cookie-without-httponly
  res.cookie("token", "", { expires: new Date(0) });
  // ok: ethos.js.auth-cookie-without-httponly
  res.cookie("token", token, { ...baseCookieOptions, maxAge: 3600_000 });
  res.json({ ok: true });
});

export async function setNextSession(accessToken: string) {
  // ruleid: ethos.js.auth-cookie-without-httponly
  cookies().set("accessToken", accessToken, { httpOnly: false, path: "/" });
  // ok: ethos.js.auth-cookie-without-httponly
  cookies().set("accessToken", accessToken, { httpOnly: true, secure: true, path: "/" });
  // Next.js cookies default to httpOnly off.
  // ruleid: ethos.js.auth-cookie-without-httponly
  cookies().set("session", accessToken);
  const response = NextResponse.json({ ok: true });
  // ruleid: ethos.js.auth-cookie-without-httponly
  response.cookies.set("refreshToken", accessToken, { secure: true, path: "/" });
  // ok: ethos.js.auth-cookie-without-httponly
  cookies().set("theme", "dark");
  return response;
}

hono.post("/login", async (c) => {
  // ruleid: ethos.js.auth-cookie-without-httponly
  setCookie(c, "auth_token", "issued-token", { secure: true, path: "/" });
  // ok: ethos.js.auth-cookie-without-httponly
  setCookie(c, "session", "issued-token", { httpOnly: true, secure: true, sameSite: "Lax" });
  return c.json({ ok: true });
});

export const workerLogin = {
  async fetch(): Promise<Response> {
    const sessionId = crypto.randomUUID();
    const headers = new Headers({ "Content-Type": "application/json" });
    // ruleid: ethos.js.auth-cookie-without-httponly
    headers.append("Set-Cookie", `session=${sessionId}; Path=/; Secure; SameSite=Lax`);
    // ok: ethos.js.auth-cookie-without-httponly
    headers.append("Set-Cookie", `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax`);
    // ok: ethos.js.auth-cookie-without-httponly
    headers.append("Set-Cookie", "session=; Max-Age=0; Path=/");
    return new Response("{}", { headers });
  },
};

app.get("/api/token-info", (req: Request, res: Response) => {
  // res.set() sets a response header, not a cookie; an expiry hint cookie is meant to be readable.
  // ok: ethos.js.auth-cookie-without-httponly
  res.set("X-Auth-Token-Expires", "3600");
  // ok: ethos.js.auth-cookie-without-httponly
  res.cookie("tokenExpiresAt", String(Date.now() + 3600_000), { secure: true, sameSite: "lax" });
  res.end();
});

app.use(
  session({
    secret: process.env.SESSION_SECRET as string,
    resave: false,
    saveUninitialized: false,
    // ruleid: ethos.js.auth-cookie-without-httponly, ethos.js.auth-cookie-secure-disabled
    cookie: { httpOnly: false, secure: false, maxAge: 86400000 },
  }),
);

// ---------------------------------------------------------------------------
// ethos.js.auth-cookie-secure-disabled
// ---------------------------------------------------------------------------
app.post("/refresh", (req: Request, res: Response) => {
  // ruleid: ethos.js.auth-cookie-secure-disabled
  res.cookie("refreshToken", req.body.rt, { httpOnly: true, secure: false });
  // ok: ethos.js.auth-cookie-secure-disabled
  res.cookie("refreshToken", req.body.rt, { httpOnly: true, secure: true });
  // ok: ethos.js.auth-cookie-secure-disabled
  res.cookie("theme", "dark", { secure: false });
  // ok: ethos.js.auth-cookie-secure-disabled
  res.cookie("refreshToken", req.body.rt, { httpOnly: true, secure: process.env.NODE_ENV === "production" });
  res.end();
});

// ---------------------------------------------------------------------------
// ethos.js.reflected-xss-from-request
// ---------------------------------------------------------------------------
app.get("/search", (req: Request, res: Response) => {
  const { q } = req.query;
  // ruleid: ethos.js.reflected-xss-from-request
  res.send(`<h1>Results for ${q}</h1>`);
});

app.get("/users/:id", (req: Request, res: Response) => {
  // ruleid: ethos.js.reflected-xss-from-request
  res.status(404).send("User " + req.params.id + " not found");
});

export const greetWorker = {
  async fetch(request: Request & { url: string }): Promise<Response> {
    const { searchParams } = new URL(request.url);
    const name = searchParams.get("name") ?? "guest";
    // ruleid: ethos.js.reflected-xss-from-request
    return new Response(`<!doctype html><h1>Welcome ${name}</h1>`, {
      headers: { "Content-Type": "text/html;charset=UTF-8" },
    });
  },
};

hono.get("/greet", (c) => {
  const who = c.req.query("who");
  // ruleid: ethos.js.reflected-xss-from-request
  return c.html(`<h1>Hello ${who}</h1>`);
});

http.createServer((req, res) => {
  const who = new URL(req.url ?? "/", "http://localhost").searchParams.get("who");
  res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
  // ruleid: ethos.js.reflected-xss-from-request
  res.end(`<p>Hi ${who}</p>`);
});

app.get("/api/search", (req: Request, res: Response) => {
  // JSON responses and objects are not rendered as HTML.
  // ok: ethos.js.reflected-xss-from-request
  res.json({ q: req.query.q });
  // ok: ethos.js.reflected-xss-from-request
  res.send({ q: req.query.q, page: 1 });
});

app.get("/hello", (req: Request, res: Response) => {
  // ok: ethos.js.reflected-xss-from-request
  res.type("text/plain").send(`Hello ${req.query.name}`);
});

app.get("/results", (req: Request, res: Response) => {
  const page = parseInt(req.query.page as string, 10) || 1;
  // ok: ethos.js.reflected-xss-from-request
  res.send(`<h1>Results for ${escapeHtml(String(req.query.q))}</h1><p>Page ${page}</p>`);
});

export const plainWorker = {
  async fetch(request: Request & { url: string }): Promise<Response> {
    const name = new URL(request.url).searchParams.get("name");
    // A string body without an HTML Content-Type is served as text/plain.
    // ok: ethos.js.reflected-xss-from-request
    return new Response(`Hello ${name}`);
  },
};

app.get("/tags/:slug", (req: Request, res: Response) => {
  if (!/^[a-z0-9-]+$/.test(req.params.slug)) return res.status(400).send("Invalid tag");
  // Validated in place before being reflected.
  // ok: ethos.js.reflected-xss-from-request
  res.send(`<h1>#${req.params.slug}</h1>`);
});
