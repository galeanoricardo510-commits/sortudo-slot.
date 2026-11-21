const COOKIE_NAME = "sortudo_session";
const SESSION_DAYS = 30;
const STARTING_CREDITS = 10000;
const PBKDF2_ITERATIONS = 120000;

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers }
  });
}
function fail(message, status = 400) { return json({ ok: false, error: message }, status); }
function randomBytes(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}
function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}
function fromBase64Url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}
async function sha256(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return toBase64Url(new Uint8Array(digest));
}
async function hashPassword(password, salt = randomBytes(16)) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key, 256
  );
  return `pbkdf2$${PBKDF2_ITERATIONS}$${toBase64Url(salt)}$${toBase64Url(new Uint8Array(bits))}`;
}
async function verifyPassword(password, stored) {
  try {
    const [scheme, iterations, saltText, expected] = stored.split("$");
    if (scheme !== "pbkdf2" || Number(iterations) !== PBKDF2_ITERATIONS) return false;
    const actual = await hashPassword(password, fromBase64Url(saltText));
    return constantTimeEqual(actual.split("$")[3], expected);
  } catch { return false; }
}
function constantTimeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
function cookie(token, maxAge) {
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const index = part.indexOf("=");
    if (index >= 0 && part.slice(0, index).trim() === name) return part.slice(index + 1).trim();
  }
  return null;
}
async function bodyJson(request) {
  try { return await request.json(); } catch { return null; }
}
function validOrigin(request) {
  const origin = request.headers.get("Origin");
  if (!origin) return true;
  try { return new URL(origin).host === new URL(request.url).host; } catch { return false; }
}
async function currentUser(request, env) {
  const token = getCookie(request, COOKIE_NAME);
  if (!token) return null;
  const tokenHash = await sha256(token);
  const row = await env.DB.prepare(
    `SELECT u.id, u.username, u.email, u.credits, u.role
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = ? AND s.expires_at > datetime('now')`
  ).bind(tokenHash).first();
  return row || null;
}
async function createSession(userId, env) {
  const token = toBase64Url(randomBytes(32));
  const tokenHash = await sha256(token);
  await env.DB.prepare(
    `INSERT INTO sessions (user_id, token_hash, expires_at)
     VALUES (?, ?, datetime('now', '+${SESSION_DAYS} days'))`
  ).bind(userId, tokenHash).run();
  return token;
}
function publicUser(user) {
  return { id: user.id, username: user.username, email: user.email, credits: user.credits, role: user.role };
}
async function handleApi(request, env) {
  if (!env.DB) return fail("La base de datos DB no está conectada en Cloudflare.", 500);
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method.toUpperCase();

  if (method !== "GET" && !validOrigin(request)) return fail("Solicitud no válida.", 403);

  if (path === "/api/me" && method === "GET") {
    const user = await currentUser(request, env);
    return json({ ok: true, user: user ? publicUser(user) : null });
  }

  if (path === "/api/register" && method === "POST") {
    const data = await bodyJson(request);
    if (!data) return fail("Datos inválidos.");
    const username = String(data.username || data.name || "").trim();
    const email = String(data.email || "").trim().toLowerCase();
    const password = String(data.password || "");
    if (username.length < 3 || username.length > 30) return fail("El nombre debe tener entre 3 y 30 caracteres.");
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return fail("Ingresá un correo válido.");
    if (password.length < 8 || password.length > 128) return fail("La contraseña debe tener entre 8 y 128 caracteres.");
    const existing = await env.DB.prepare("SELECT id FROM users WHERE lower(email) = ? OR lower(username) = ?").bind(email, username.toLowerCase()).first();
    if (existing) return fail("Ese correo o nombre de usuario ya está registrado.", 409);
    const passwordHash = await hashPassword(password);
    try {
      const result = await env.DB.prepare(
        "INSERT INTO users (username, email, password_hash, credits, role) VALUES (?, ?, ?, ?, 'player')"
      ).bind(username, email, passwordHash, STARTING_CREDITS).run();
      const userId = result.meta.last_row_id;
      const token = await createSession(userId, env);
      const user = await env.DB.prepare("SELECT id, username, email, credits, role FROM users WHERE id = ?").bind(userId).first();
      return json({ ok: true, user: publicUser(user) }, 201, { "set-cookie": cookie(token, SESSION_DAYS * 86400) });
    } catch (error) {
      return fail("No se pudo crear la cuenta. Probá con otro correo o nombre.", 409);
    }
  }

  if (path === "/api/login" && method === "POST") {
    const data = await bodyJson(request);
    if (!data) return fail("Datos inválidos.");
    const identifier = String(data.email || data.username || data.login || "").trim().toLowerCase();
    const password = String(data.password || "");
    if (!identifier || !password) return fail("Completá tus datos.");
    const user = await env.DB.prepare(
      "SELECT id, username, email, password_hash, credits, role FROM users WHERE lower(email) = ? OR lower(username) = ?"
    ).bind(identifier, identifier).first();
    if (!user || !(await verifyPassword(password, user.password_hash))) return fail("Correo o contraseña incorrectos.", 401);
    const token = await createSession(user.id, env);
    return json({ ok: true, user: publicUser(user) }, 200, { "set-cookie": cookie(token, SESSION_DAYS * 86400) });
  }

  if (path === "/api/logout" && method === "POST") {
    const token = getCookie(request, COOKIE_NAME);
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(await sha256(token)).run();
    return json({ ok: true }, 200, { "set-cookie": cookie("", 0) });
  }

  if (path === "/api/spin" && method === "POST") {
    const user = await currentUser(request, env);
    if (!user) return fail("Iniciá sesión para jugar.", 401);
    const data = await bodyJson(request);
    const bet = Number(data && data.bet);
    const gameSlug = String((data && data.game) || (data && data.game_slug) || "lucky-spin").slice(0, 60);
    if (!Number.isSafeInteger(bet) || bet < 100 || bet > 1000) return fail("La apuesta debe ser entre 100 y 1.000 créditos.");
    const win = Math.random() < 0.12;
    const prize = win ? (Math.random() < 0.15 ? bet * 10 : bet * 2) : 0;
    const update = await env.DB.prepare(
      "UPDATE users SET credits = credits - ? + ? WHERE id = ? AND credits >= ?"
    ).bind(bet, prize, user.id, bet).run();
    if (!update.meta.changes) return fail("No tenés créditos suficientes.", 400);
    await env.DB.prepare(
      "INSERT INTO game_history (user_id, game_slug, bet, prize) VALUES (?, ?, ?, ?)"
    ).bind(user.id, gameSlug, bet, prize).run();
    const updated = await env.DB.prepare("SELECT credits FROM users WHERE id = ?").bind(user.id).first();
    return json({ ok: true, bet, prize, won: prize > 0, credits: updated.credits });
  }

  if (path === "/api/admin/claim" && method === "POST") {
    const user = await currentUser(request, env);
    if (!user) return fail("Iniciá sesión primero.", 401);
    if (!env.ADMIN_EMAIL || !env.ADMIN_SETUP_KEY) return fail("Faltan configurar ADMIN_EMAIL y ADMIN_SETUP_KEY en Cloudflare.", 500);
    const data = await bodyJson(request);
    const email = String(data && data.email || user.email).trim().toLowerCase();
    const key = String(data && (data.setupKey || data.key) || "");
    if (email !== String(env.ADMIN_EMAIL).trim().toLowerCase() || user.email.toLowerCase() !== email) return fail("Esta cuenta no está autorizada como administradora.", 403);
    if (!constantTimeEqual(key, env.ADMIN_SETUP_KEY)) return fail("Clave de configuración incorrecta.", 403);
    const adminExists = await env.DB.prepare("SELECT id FROM users WHERE role = 'admin' AND id <> ?").bind(user.id).first();
    if (adminExists) return fail("Ya existe una cuenta administradora.", 409);
    await env.DB.prepare("UPDATE users SET role = 'admin' WHERE id = ?").bind(user.id).run();
    const updated = await env.DB.prepare("SELECT id, username, email, credits, role FROM users WHERE id = ?").bind(user.id).first();
    return json({ ok: true, user: publicUser(updated) });
  }

  if (path === "/api/admin/stats" && method === "GET") {
    const user = await currentUser(request, env);
    if (!user || user.role !== "admin") return fail("Acceso denegado.", 403);
    const stats = await env.DB.prepare(
      "SELECT COUNT(*) AS total_users, COALESCE(SUM(credits), 0) AS total_credits FROM users"
    ).first();
    const recent = await env.DB.prepare(
      "SELECT username, email, credits, created_at FROM users ORDER BY id DESC LIMIT 20"
    ).all();
    return json({ ok: true, stats, users: recent.results || [] });
  }

  if (path === "/api/admin/reset-demo" && method === "POST") {
    const user = await currentUser(request, env);
    if (!user || user.role !== "admin") return fail("Acceso denegado.", 403);
    await env.DB.batch([
      env.DB.prepare("UPDATE users SET credits = ?").bind(STARTING_CREDITS),
      env.DB.prepare("DELETE FROM game_history")
    ]);
    return json({ ok: true, message: "Créditos de demostración reiniciados." });
  }

  return fail("Ruta no encontrada.", 404);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) {
      try { return await handleApi(request, env); }
      catch (error) {
        return json({ ok: false, error: "Error interno del servidor. Revisá la configuración de Cloudflare." }, 500);
      }
    }
    if (env.ASSETS && typeof env.ASSETS.fetch === "function") return env.ASSETS.fetch(request);
    return new Response("No se encontró el servicio de archivos estáticos ASSETS.", { status: 500 });
  }
};
