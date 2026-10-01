import jwt from "jsonwebtoken";

// ruleid: ethos.js.secret-env-fallback
const JWT_SECRET = process.env.JWT_SECRET || "dev-secret";

// ruleid: ethos.js.secret-env-fallback
const sessionSecret: string = process.env.SESSION_SECRET ?? "keyboard cat";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // ruleid: ethos.js.secret-env-fallback
    const token = jwt.sign({ sub: "1" }, env.AUTH_TOKEN_SECRET || "local-secret");
    return new Response(token);
  },
};

// ok: ethos.js.secret-env-fallback
const strictSecret = process.env.JWT_SECRET!;

// ok: ethos.js.secret-env-fallback
const expiresIn = process.env.TOKEN_EXPIRES_IN_SECONDS || "3600";

// ok: ethos.js.secret-env-fallback
const apiUrl = process.env.API_URL || "http://localhost:3000";

// ok: ethos.js.secret-env-fallback
const optionalToken = process.env.SENTRY_TOKEN || "";

// ok: ethos.js.secret-env-fallback
const tokenHeader = process.env.TOKEN_HEADER ?? "Authorization";

export { JWT_SECRET, sessionSecret, strictSecret, expiresIn, apiUrl, optionalToken, tokenHeader };
