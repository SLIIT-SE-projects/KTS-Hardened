// Simple fixed-window gate (per Node process). Use Redis for multi-instance.
const buckets = new Map(); // key -> { count, resetAt }

function now() { return Date.now(); }

function allow({ key, max, windowMs }) {
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

module.exports = { allow };
