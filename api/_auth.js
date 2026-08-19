import crypto from 'node:crypto';

export const SESSION_COOKIE = '__Host-elite_dashboard_session';
const SESSION_TTL_SECONDS = 4 * 60 * 60;

function getSessionSecret() {
  const secret = process.env.SESSION_SECRET;
  if (!secret || secret.length < 32) {
    throw new Error('SESSION_SECRET must be at least 32 characters');
  }
  return secret;
}

function encode(value) {
  return Buffer.from(value).toString('base64url');
}

function sign(value) {
  return crypto.createHmac('sha256', getSessionSecret()).update(value).digest('base64url');
}

function safeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function passwordsMatch(candidate) {
  const password = process.env.DASHBOARD_PASSWORD;
  if (!password) throw new Error('DASHBOARD_PASSWORD is not configured');
  return typeof candidate === 'string' && safeEqual(candidate, password);
}

export function createSessionToken() {
  const payload = encode(JSON.stringify({
    exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
    nonce: crypto.randomBytes(16).toString('base64url')
  }));
  return `${payload}.${sign(payload)}`;
}

export function isAuthenticated(req) {
  const cookieHeader = req.headers.cookie || '';
  const cookies = Object.fromEntries(cookieHeader.split(';').map(part => {
    const index = part.indexOf('=');
    return index === -1 ? [part.trim(), ''] : [part.slice(0, index).trim(), part.slice(index + 1)];
  }));
  const token = cookies[SESSION_COOKIE];
  if (!token) return false;

  const separator = token.lastIndexOf('.');
  if (separator < 1) return false;
  const payload = token.slice(0, separator);
  const signature = token.slice(separator + 1);

  try {
    if (!safeEqual(signature, sign(payload))) return false;
    const session = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return Number.isSafeInteger(session.exp) && session.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

export function sessionCookie(token) {
  return `${SESSION_COOKIE}=${token}; Max-Age=${SESSION_TTL_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

export function clearSessionCookie() {
  return `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict`;
}

export function noStore(res) {
  res.setHeader('Cache-Control', 'no-store');
}
