const { ipKeyGenerator } = require("express-rate-limit");

const buckets = new Map(); // key -> { count, resetAt }
const DEFAULT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const DEFAULT_MAX = 20;

// --- Internal helpers ---
function now() {
  return Date.now();
}

function canonicalCallerKey(req) {
  // Prefer a stable user id after auth; otherwise IPv6-safe IP key.
  const base = req.user?.id ? `u:${req.user.id}` : `ip:${ipKeyGenerator(req.ip)}`;
  return base;
}

function makeKey(req, bucket) {
  return `${canonicalCallerKey(req)}:${bucket}`;
}

// Core fixed-window allow function
function allow(key, max, windowMs) {
  const k = String(key);
  const t = now();
  const b = buckets.get(k);

  if (!b || t > b.resetAt) {
    const resetAt = t + windowMs;
    buckets.set(k, { count: 1, resetAt });
    return { allowed: true, remaining: max - 1, resetAt };
  }

  if (b.count < max) {
    b.count += 1;
    return { allowed: true, remaining: max - b.count, resetAt: b.resetAt };
  }

  return { allowed: false, remaining: 0, resetAt: b.resetAt };
}

// Set standard headers when denying 
function setRateHeaders(res, { limit, remaining, resetAt }) {
  res.set("RateLimit-Limit", String(limit));
  res.set("RateLimit-Remaining", String(Math.max(remaining, 0)));
  res.set("RateLimit-Reset", String(Math.ceil(resetAt / 1000))); // seconds epoch
}

// --- Public API ---

// Call this at the TOP of a controller. Returns true if allowed; otherwise
// writes 429 + headers and returns false (caller should `return` immediately).
function enforceGate(req, res, opts = {}) {
  const bucket = opts.bucket || "default";
  const max =
    Number(opts.max ?? process.env.RATE_CREATE_MAX ?? DEFAULT_MAX);
  const windowMs =
    Number(opts.windowMs ?? process.env.RATE_WINDOW_MS ?? DEFAULT_WINDOW_MS);

  const key = makeKey(req, bucket);
  const decision = allow(key, max, windowMs);

  if (!decision.allowed) {
    setRateHeaders(res, { limit: max, remaining: decision.remaining, resetAt: decision.resetAt });
    res.status(429).json({ error: "Too many requests. Please try again later." });
    return false;
  }
  return true;
}

// lightweight periodic pruning to prevent memory growth.
const PRUNE_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes
setInterval(() => {
  const t = now();
  for (const [k, v] of buckets.entries()) {
    if (t > v.resetAt) buckets.delete(k);
  }
}, PRUNE_INTERVAL_MS).unref();

module.exports = {
  enforceGate,
  makeKey,
  allow,
};
