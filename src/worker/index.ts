import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { Hono, Context } from "hono";
import { createMiddleware } from "hono/factory";

type RateLimiterBinding = {
  limit: (options: { key: string }) => Promise<{ success: boolean }>;
};

type Variables = {
  auth: {
    sessionId: string;
    tokenHash: string;
    user: {
      id: string;
      username: string;
      description: string;
    };
  };
};

type AppEnv = {
  Bindings: Env;
  Variables: Variables;
};

type UserForLogin = {
  id: string;
  username: string;
  description: string;
  verified_at: string | null;
  password_hash: string;
  password_salt: string;
};

type AuthRow = {
  session_id: string;
  user_id: string;
  username: string;
  description: string;
  verified_at: string | null;
  expires_at: string;
};

type PointRow = {
  id: string;
  delta: number;
  reason: string;
  created_at: string;
};

type TotalRow = {
  total: number | string;
};

type PointRequestRow = {
  id: string;
  user_id: string;
  amount: number;
  reason: string;
  status: string;
  rejection_reason: string | null;
  created_at: string;
  updated_at: string;
};

type AdminPointRequestRow = PointRequestRow & {
  username: string;
};

type PendingUserRow = {
  id: string;
  username: string;
  description: string;
  created_at: string;
};

const ADMIN_USERNAME = "miquel";

const USERNAME_REGEX = /^[a-z0-9_]{3,24}$/;
const DESCRIPTION_MAX_LENGTH = 280;
const DESCRIPTION_MAX_LINES = 2;

const PASSWORD_PBKDF2_ITERATIONS = 60_000;
const PASSWORD_SALT_BYTES = 16;
const PASSWORD_HASH_BYTES = 32;

const SESSION_COOKIE_NAME = "points_session";
const SESSION_TOKEN_BYTES = 32;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

const DEFAULT_POINTS_PAGE_LIMIT = 20;
const MAX_POINTS_PAGE_LIMIT = 100;

const app = new Hono<AppEnv>();
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function isDev(value: string | boolean | undefined): boolean {
  if (typeof value === "boolean") {
    return value;
  }

  if (typeof value === "string") {
    return value.toLowerCase() === "true";
  }

  return false;
}

function jsonError(c: Context<AppEnv>, status: number, error: string) {
  return c.json({ error }, status as 400 | 401 | 403 | 404 | 409 | 429 | 500);
}

function getClientKey(c: Context<AppEnv>): string {
  const directIp = c.req.header("CF-Connecting-IP");
  if (directIp) {
    return directIp;
  }

  const forwarded = c.req.header("X-Forwarded-For");
  if (forwarded) {
    return forwarded.split(",")[0]?.trim() ?? "unknown";
  }

  return "unknown";
}

function normalizeUsername(username: string): string {
  return username.trim().toLowerCase();
}

function normalizeDescription(description: string): string {
  return description.trim();
}

function validateUsername(username: string): string | null {
  if (!USERNAME_REGEX.test(username)) {
    return "Username must match [a-z0-9_]{3,24}";
  }
  return null;
}

function validateDescription(description: string): string | null {
  if (description.length === 0) {
    return "Description is required";
  }

  if (description.length > DESCRIPTION_MAX_LENGTH) {
    return `Description must be at most ${DESCRIPTION_MAX_LENGTH} characters`;
  }

  const lines = description.split(/\r?\n/);
  if (lines.length > DESCRIPTION_MAX_LINES) {
    return "Description must be one or two lines";
  }

  if (lines.some((line) => line.trim().length === 0)) {
    return "Description lines cannot be empty";
  }

  return null;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex length");
  }

  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    const pair = hex.slice(i * 2, i * 2 + 2);
    const value = Number.parseInt(pair, 16);
    if (Number.isNaN(value)) {
      throw new Error("Invalid hex value");
    }
    bytes[i] = value;
  }

  return bytes;
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }

  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return diff === 0;
}

async function pbkdf2Hash(password: string, saltHex: string, pepper: string): Promise<string> {
  const saltBytes = hexToBytes(saltHex);
  const saltBuffer = saltBytes.buffer.slice(saltBytes.byteOffset, saltBytes.byteOffset + saltBytes.byteLength);

  const keyMaterial = await crypto.subtle.importKey("raw", textEncoder.encode(`${password}\u0000${pepper}`), { name: "PBKDF2" }, false, ["deriveBits"]);

  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: PASSWORD_PBKDF2_ITERATIONS,
      salt: saltBuffer,
    },
    keyMaterial,
    PASSWORD_HASH_BYTES * 8,
  );

  return bytesToHex(new Uint8Array(derived));
}

async function hashPassword(password: string, saltHex: string, pepper: string): Promise<string> {
  return pbkdf2Hash(password, saltHex, pepper);
}

async function verifyPassword(options: { password: string; saltHex: string; expectedHashHex: string; pepper: string }): Promise<boolean> {
  const actual = await pbkdf2Hash(options.password, options.saltHex, options.pepper);
  return timingSafeEqual(actual, options.expectedHashHex);
}

function generateSaltHex(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(PASSWORD_SALT_BYTES)));
}

function generateSessionToken(): string {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(SESSION_TOKEN_BYTES)));
}

async function hashSessionToken(token: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", textEncoder.encode(token));
  return bytesToHex(new Uint8Array(digest));
}

function encodeCursor(payload: { createdAt: string; id: string }): string {
  const bytes = textEncoder.encode(JSON.stringify(payload));
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeCursor(cursor: string): { createdAt: string; id: string } | null {
  try {
    const normalized = cursor.replace(/-/g, "+").replace(/_/g, "/");
    const padding = normalized.length % 4 === 0 ? "" : "=".repeat(4 - (normalized.length % 4));
    const binary = atob(normalized + padding);
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    const parsed = JSON.parse(textDecoder.decode(bytes)) as unknown;

    if (typeof parsed !== "object" || parsed === null || !("createdAt" in parsed) || !("id" in parsed) || typeof (parsed as Record<string, unknown>).createdAt !== "string" || typeof (parsed as Record<string, unknown>).id !== "string") {
      return null;
    }

    return {
      createdAt: (parsed as Record<string, string>).createdAt,
      id: (parsed as Record<string, string>).id,
    };
  } catch {
    return null;
  }
}

async function enforceRateLimit(c: Context<AppEnv>, limiter: RateLimiterBinding | undefined, errorMessage: string) {
  if (!limiter) {
    return null;
  }

  try {
    const result = await limiter.limit({ key: getClientKey(c) });
    if (!result.success) {
      return c.json({ error: errorMessage }, 429);
    }
  } catch (error) {
    console.error("Rate limit binding failed:", error);
  }

  return null;
}

function setSessionCookie(c: Context<AppEnv>, token: string, devMode: boolean): void {
  setCookie(c, SESSION_COOKIE_NAME, token, {
    path: "/",
    httpOnly: true,
    secure: !devMode,
    sameSite: "Lax",
    maxAge: Math.floor(SESSION_TTL_MS / 1000),
  });
}

function clearSessionCookie(c: Context<AppEnv>, devMode: boolean): void {
  deleteCookie(c, SESSION_COOKIE_NAME, {
    path: "/",
    httpOnly: true,
    secure: !devMode,
    sameSite: "Lax",
  });
}

async function getTotalPoints(db: D1Database, userId: string): Promise<number> {
  const row = await db.prepare("SELECT COALESCE(SUM(delta), 0) AS total FROM points WHERE user_id = ?").bind(userId).first<TotalRow>();

  const value = Number(row?.total ?? 0);
  return Number.isFinite(value) ? value : 0;
}

async function queryPointsPage(options: { db: D1Database; userId: string; limit: number; cursor: { createdAt: string; id: string } | null }) {
  const limitWithSentinel = options.limit + 1;

  const statement = options.cursor
    ? options.db
        .prepare(
          `SELECT id, delta, reason, created_at
           FROM points
           WHERE user_id = ?
             AND (created_at < ? OR (created_at = ? AND id < ?))
           ORDER BY created_at DESC, id DESC
           LIMIT ?`,
        )
        .bind(options.userId, options.cursor.createdAt, options.cursor.createdAt, options.cursor.id, limitWithSentinel)
    : options.db
        .prepare(
          `SELECT id, delta, reason, created_at
           FROM points
           WHERE user_id = ?
           ORDER BY created_at DESC, id DESC
           LIMIT ?`,
        )
        .bind(options.userId, limitWithSentinel);

  const { results } = await statement.all<PointRow>();
  const rows = results ?? [];
  const hasMore = rows.length > options.limit;
  const items = hasMore ? rows.slice(0, options.limit) : rows;
  const last = items.at(-1);
  const nextCursor = hasMore && last ? encodeCursor({ createdAt: last.created_at, id: last.id }) : null;

  return {
    items: items.map((item) => ({
      id: item.id,
      delta: Number(item.delta),
      reason: item.reason,
      createdAt: item.created_at,
    })),
    nextCursor,
  };
}

async function loadAuthContext(c: Context<AppEnv>, options: { touchSession: boolean }) {
  const token = getCookie(c, SESSION_COOKIE_NAME);
  if (!token) {
    return null;
  }

  const now = new Date();
  const nowIso = now.toISOString();
  const tokenHash = await hashSessionToken(token);

  const row = await c.env.points_db
    .prepare(
      `SELECT
        s.id AS session_id,
        s.user_id AS user_id,
        s.expires_at AS expires_at,
        u.username AS username,
        u.description AS description,
        u.verified_at AS verified_at
      FROM sessions s
      INNER JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = ?
        AND s.revoked_at IS NULL
        AND s.expires_at > ?
      LIMIT 1`,
    )
    .bind(tokenHash, nowIso)
    .first<AuthRow>();

  const devMode = isDev(c.env.DEV);
  if (!row || !row.verified_at) {
    clearSessionCookie(c, devMode);
    return null;
  }

  if (options.touchSession) {
    const expiresAt = new Date(row.expires_at);
    const remainingMs = expiresAt.getTime() - now.getTime();

    if (remainingMs < SESSION_TTL_MS / 2) {
      const refreshedExpiry = new Date(now.getTime() + SESSION_TTL_MS).toISOString();
      await c.env.points_db.prepare("UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?").bind(refreshedExpiry, nowIso, row.session_id).run();
      setSessionCookie(c, token, devMode);
    } else {
      await c.env.points_db.prepare("UPDATE sessions SET last_seen_at = ? WHERE id = ?").bind(nowIso, row.session_id).run();
    }
  }

  return {
    sessionId: row.session_id,
    tokenHash,
    user: {
      id: row.user_id,
      username: row.username,
      description: row.description,
    },
  };
}

const requireAuth = createMiddleware<AppEnv>(async (c, next) => {
  const auth = await loadAuthContext(c, { touchSession: true });
  if (!auth) {
    return c.json({ error: "UNAUTHENTICATED" }, 401);
  }

  c.set("auth", auth);
  await next();
});

const requireAdmin = createMiddleware<AppEnv>(async (c, next) => {
  const auth = c.get("auth");
  if (auth.user.username !== ADMIN_USERNAME) {
    return jsonError(c, 403, "Unauthorized");
  }
  await next();
});

app.post("/api/auth/signup", async (c) => {
  const rateLimitResponse = await enforceRateLimit(c, c.env.RATE_LIMITER, "Too many signup attempts");
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  let payload: unknown;
  try {
    payload = await c.req.json();
  } catch {
    return jsonError(c, 400, "Invalid JSON body");
  }

  const body = payload as { username?: unknown; password?: unknown; description?: unknown };
  const username = normalizeUsername(typeof body.username === "string" ? body.username : "");
  const password = typeof body.password === "string" ? body.password : "";
  const description = normalizeDescription(typeof body.description === "string" ? body.description : "");

  const usernameError = validateUsername(username);
  if (usernameError) {
    return jsonError(c, 400, usernameError);
  }

  const descriptionError = validateDescription(description);
  if (descriptionError) {
    return jsonError(c, 400, descriptionError);
  }

  const saltHex = generateSaltHex();
  const passwordHash = await hashPassword(password, saltHex, c.env.PASSWORD_PEPPER);

  try {
    await c.env.points_db
      .prepare(
        `INSERT INTO users (id, username, password_hash, password_salt, description)
         VALUES (?, ?, ?, ?, ?)`,
      )
      .bind(crypto.randomUUID(), username, passwordHash, saltHex, description)
      .run();
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (message.includes("UNIQUE") || message.includes("constraint")) {
      return jsonError(c, 409, "Username already exists");
    }

    console.error("Signup failed:", error);
    return jsonError(c, 500, "Failed to create user");
  }

  return c.json(
    {
      ok: true,
      user: {
        username,
      },
    },
    201,
  );
});

app.post("/api/auth/login", async (c) => {
  const rateLimitResponse = await enforceRateLimit(c, c.env.RATE_LIMITER, "Too many login attempts");
  if (rateLimitResponse) {
    return rateLimitResponse;
  }

  let payload: unknown;
  try {
    payload = await c.req.json();
  } catch {
    return jsonError(c, 400, "Invalid JSON body");
  }

  const body = payload as { username?: unknown; password?: unknown };
  const username = normalizeUsername(typeof body.username === "string" ? body.username : "");
  const password = typeof body.password === "string" ? body.password : "";

  if (!username || !password) {
    return jsonError(c, 400, "Username and password are required");
  }

  const user = await c.env.points_db
    .prepare(
      `SELECT id, username, description, verified_at, password_hash, password_salt
       FROM users
       WHERE username = ? COLLATE NOCASE
       LIMIT 1`,
    )
    .bind(username)
    .first<UserForLogin>();

  if (!user) {
    return jsonError(c, 401, "Invalid credentials");
  }

  const passwordOk = await verifyPassword({
    password,
    saltHex: user.password_salt,
    expectedHashHex: user.password_hash,
    pepper: c.env.PASSWORD_PEPPER,
  });

  if (!passwordOk) {
    return jsonError(c, 401, "Invalid credentials");
  }

  if (!user.verified_at) {
    return jsonError(c, 403, "UNVERIFIED_USER");
  }

  const token = generateSessionToken();
  const tokenHash = await hashSessionToken(token);
  const now = new Date();
  const nowIso = now.toISOString();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS).toISOString();

  await c.env.points_db
    .prepare(
      `INSERT INTO sessions (id, user_id, token_hash, expires_at, last_seen_at)
       VALUES (?, ?, ?, ?, ?)`,
    )
    .bind(crypto.randomUUID(), user.id, tokenHash, expiresAt, nowIso)
    .run();

  setSessionCookie(c, token, isDev(c.env.DEV));

  return c.json({
    ok: true,
    user: {
      id: user.id,
      username: user.username,
    },
  });
});

app.post("/api/auth/logout", async (c) => {
  const token = getCookie(c, SESSION_COOKIE_NAME);
  if (token) {
    const nowIso = new Date().toISOString();
    const tokenHash = await hashSessionToken(token);
    await c.env.points_db.prepare("UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL").bind(nowIso, tokenHash).run();
  }

  clearSessionCookie(c, isDev(c.env.DEV));
  return c.json({ ok: true });
});

app.get("/api/auth/me", requireAuth, async (c) => {
  const auth = c.get("auth");
  const totalPoints = await getTotalPoints(c.env.points_db, auth.user.id);

  return c.json({
    user: {
      id: auth.user.id,
      username: auth.user.username,
      description: auth.user.description,
      isAdmin: auth.user.username === ADMIN_USERNAME,
    },
    totalPoints,
  });
});

app.get("/api/points", requireAuth, async (c) => {
  const auth = c.get("auth");

  const rawLimit = c.req.query("limit");
  const parsedLimit = Number.parseInt(rawLimit ?? "", 10);
  const limit = Number.isFinite(parsedLimit) ? Math.max(1, Math.min(MAX_POINTS_PAGE_LIMIT, parsedLimit)) : DEFAULT_POINTS_PAGE_LIMIT;

  const rawCursor = c.req.query("cursor");
  const cursor = rawCursor ? decodeCursor(rawCursor) : null;
  if (rawCursor && !cursor) {
    return jsonError(c, 400, "Invalid cursor");
  }

  const [totalPoints, page] = await Promise.all([
    getTotalPoints(c.env.points_db, auth.user.id),
    queryPointsPage({
      db: c.env.points_db,
      userId: auth.user.id,
      limit,
      cursor,
    }),
  ]);

  return c.json({
    totalPoints,
    items: page.items,
    nextCursor: page.nextCursor,
  });
});

// --- Point requests (user) ---

app.post("/api/requests", requireAuth, async (c) => {
  let payload: unknown;
  try {
    payload = await c.req.json();
  } catch {
    return jsonError(c, 400, "Invalid JSON body");
  }

  const body = payload as { amount?: unknown; reason?: unknown };
  const amount = typeof body.amount === "number" ? Math.floor(body.amount) : 0;
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";

  if (amount <= 0) {
    return jsonError(c, 400, "Amount must be a positive integer");
  }

  if (!reason || reason.length > 280) {
    return jsonError(c, 400, "Reason is required (max 280 characters)");
  }

  const auth = c.get("auth");
  await c.env.points_db
    .prepare("INSERT INTO point_requests (id, user_id, amount, reason) VALUES (?, ?, ?, ?)")
    .bind(crypto.randomUUID(), auth.user.id, amount, reason)
    .run();

  return c.json({ ok: true }, 201);
});

app.get("/api/requests", requireAuth, async (c) => {
  const auth = c.get("auth");
  const { results } = await c.env.points_db
    .prepare(
      `SELECT id, amount, reason, status, rejection_reason, created_at
       FROM point_requests
       WHERE user_id = ?
       ORDER BY created_at DESC`,
    )
    .bind(auth.user.id)
    .all<PointRequestRow>();

  return c.json({
    requests: (results ?? []).map((r) => ({
      id: r.id,
      amount: r.amount,
      reason: r.reason,
      status: r.status,
      rejectionReason: r.rejection_reason,
      createdAt: r.created_at,
    })),
  });
});

app.put("/api/requests/:id", requireAuth, async (c) => {
  const auth = c.get("auth");
  const requestId = c.req.param("id");

  let payload: unknown;
  try {
    payload = await c.req.json();
  } catch {
    return jsonError(c, 400, "Invalid JSON body");
  }

  const body = payload as { amount?: unknown; reason?: unknown };
  const amount = typeof body.amount === "number" ? Math.floor(body.amount) : 0;
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";

  if (amount <= 0) {
    return jsonError(c, 400, "Amount must be a positive integer");
  }

  if (!reason || reason.length > 280) {
    return jsonError(c, 400, "Reason is required (max 280 characters)");
  }

  const existing = await c.env.points_db
    .prepare("SELECT id, user_id, status FROM point_requests WHERE id = ? LIMIT 1")
    .bind(requestId)
    .first<{ id: string; user_id: string; status: string }>();

  if (!existing || existing.user_id !== auth.user.id) {
    return jsonError(c, 404, "Request not found");
  }

  if (existing.status !== "rejected") {
    return jsonError(c, 400, "Only rejected requests can be resubmitted");
  }

  const nowIso = new Date().toISOString();
  await c.env.points_db
    .prepare("UPDATE point_requests SET amount = ?, reason = ?, status = 'pending', rejection_reason = NULL, updated_at = ? WHERE id = ?")
    .bind(amount, reason, nowIso, requestId)
    .run();

  return c.json({ ok: true });
});

// --- Point requests (admin) ---

app.get("/api/admin/users/pending", requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.points_db
    .prepare(
      `SELECT id, username, description, created_at
       FROM users
       WHERE verified_at IS NULL
       ORDER BY created_at ASC`,
    )
    .all<PendingUserRow>();

  return c.json({
    users: (results ?? []).map((user) => ({
      id: user.id,
      username: user.username,
      description: user.description,
      createdAt: user.created_at,
    })),
  });
});

app.post("/api/admin/users/:id/verify", requireAuth, requireAdmin, async (c) => {
  const userId = c.req.param("id");
  const nowIso = new Date().toISOString();

  const result = await c.env.points_db
    .prepare("UPDATE users SET verified_at = ? WHERE id = ? AND verified_at IS NULL")
    .bind(nowIso, userId)
    .run();

  if (!result.meta.changes) {
    return jsonError(c, 404, "User not found or already verified");
  }

  return c.json({ ok: true });
});

app.get("/api/admin/requests", requireAuth, requireAdmin, async (c) => {
  const { results } = await c.env.points_db
    .prepare(
      `SELECT pr.id, pr.user_id, pr.amount, pr.reason, pr.status, pr.rejection_reason, pr.created_at, u.username
       FROM point_requests pr
       INNER JOIN users u ON u.id = pr.user_id
       WHERE pr.status = 'pending'
       ORDER BY pr.created_at ASC`,
    )
    .all<AdminPointRequestRow>();

  return c.json({
    requests: (results ?? []).map((r) => ({
      id: r.id,
      userId: r.user_id,
      username: r.username,
      amount: r.amount,
      reason: r.reason,
      createdAt: r.created_at,
    })),
  });
});

app.post("/api/admin/requests/:id/accept", requireAuth, requireAdmin, async (c) => {
  const requestId = c.req.param("id");

  let payload: unknown;
  try {
    payload = await c.req.json();
  } catch {
    payload = {};
  }

  const body = payload as { amount?: unknown };
  const overrideAmount = typeof body.amount === "number" ? Math.floor(body.amount) : null;

  if (overrideAmount !== null && overrideAmount <= 0) {
    return jsonError(c, 400, "Amount must be a positive integer");
  }

  const request = await c.env.points_db
    .prepare("SELECT id, user_id, amount, reason FROM point_requests WHERE id = ? AND status = 'pending' LIMIT 1")
    .bind(requestId)
    .first<{ id: string; user_id: string; amount: number; reason: string }>();

  if (!request) {
    return jsonError(c, 404, "Request not found or not pending");
  }

  const finalAmount = overrideAmount ?? request.amount;

  const batchResults = await c.env.points_db.batch([
    c.env.points_db
      .prepare(
        `INSERT INTO points (id, user_id, delta, reason, created_by)
         SELECT ?, pr.user_id, ?, pr.reason, 'request'
         FROM point_requests pr
         WHERE pr.id = ? AND pr.status = 'pending'`,
      )
      .bind(crypto.randomUUID(), finalAmount, requestId),
    c.env.points_db.prepare("DELETE FROM point_requests WHERE id = ? AND status = 'pending'").bind(requestId),
  ]);

  if (!batchResults[0].meta.changes) {
    return jsonError(c, 404, "Request already processed");
  }

  return c.json({ ok: true });
});

app.post("/api/admin/requests/:id/reject", requireAuth, requireAdmin, async (c) => {
  const requestId = c.req.param("id");

  let payload: unknown;
  try {
    payload = await c.req.json();
  } catch {
    return jsonError(c, 400, "Invalid JSON body");
  }

  const body = payload as { reason?: unknown };
  const reason = typeof body.reason === "string" ? body.reason.trim() : "";

  if (!reason) {
    return jsonError(c, 400, "Rejection reason is required");
  }

  const nowIso = new Date().toISOString();
  const result = await c.env.points_db
    .prepare("UPDATE point_requests SET status = 'rejected', rejection_reason = ?, updated_at = ? WHERE id = ? AND status = 'pending'")
    .bind(reason, nowIso, requestId)
    .run();

  if (!result.meta.changes) {
    return jsonError(c, 404, "Request not found or not pending");
  }

  return c.json({ ok: true });
});

app.notFound((c) => jsonError(c, 404, "Not found"));

app.onError((error, c) => {
  console.error("Unhandled worker error:", error);
  return jsonError(c, 500, "Internal server error");
});

export default app;
