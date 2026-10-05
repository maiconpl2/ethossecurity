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

// ruleid: ethos.js.secret-env-fallback
const adminPassword = process.env.ADMIN_PASSWORD || "admin";

// ruleid: ethos.js.secret-env-fallback
const adminTokens = process.env.ADMIN_TOKENS ?? "token-a,token-b";

// ok: ethos.js.secret-env-fallback
const strictSecret = process.env.JWT_SECRET!;

// ok: ethos.js.secret-env-fallback
const maxTokens = Number(process.env.MAX_TOKENS || "1024");

// ok: ethos.js.secret-env-fallback
const openaiMaxTokens = process.env.OPENAI_MAX_TOKENS ?? "4096";

// ok: ethos.js.secret-env-fallback
const accessTokenTtl = process.env.ACCESS_TOKEN_EXPIRES_IN || "15m";

// ok: ethos.js.secret-env-fallback
const refreshTokenTtl = process.env.REFRESH_TOKEN_EXPIRES_IN ?? "7d";

// ok: ethos.js.secret-env-fallback
const authCookie = process.env.AUTH_TOKEN_COOKIE || "auth_token";

// ok: ethos.js.secret-env-fallback
const resetTimeout = process.env.PASSWORD_RESET_TIMEOUT || "3600";

// ok: ethos.js.secret-env-fallback
const expiresIn = process.env.TOKEN_EXPIRES_IN_SECONDS || "3600";

// ok: ethos.js.secret-env-fallback
const apiUrl = process.env.API_URL || "http://localhost:3000";

// ok: ethos.js.secret-env-fallback
const optionalToken = process.env.SENTRY_TOKEN || "";

// ok: ethos.js.secret-env-fallback
const tokenHeader = process.env.TOKEN_HEADER ?? "Authorization";

export {
  JWT_SECRET, sessionSecret, adminPassword, adminTokens, strictSecret, maxTokens, openaiMaxTokens, accessTokenTtl,
  refreshTokenTtl, authCookie, resetTimeout, expiresIn, apiUrl, optionalToken, tokenHeader,
};
