const sanitizeHtml = require("sanitize-html");
const escapeHtml = require("escape-html");

// Treat user-provided values as TEXT, not HTML. No tags allowed.
function cleanText(v) {
  // Drop all tags/attrs, then escape just in case (defense-in-depth)
  const stripped = sanitizeHtml(String(v ?? ""), { allowedTags: [], allowedAttributes: {} });
  return escapeHtml(stripped);
}

// Only allow https or data: PNG. Return "" if invalid.
function cleanQrSrc(v) {
  const s = String(v ?? "");
  try {
    const u = new URL(s);
    const httpsOk = u.protocol === "https:";
    const dataPngOk = s.startsWith("data:image/png;base64,");
    return (httpsOk || dataPngOk) ? s : "";
  } catch {
    return "";
  }
}

module.exports = { cleanText, cleanQrSrc };
