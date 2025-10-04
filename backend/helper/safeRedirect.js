// helpers/safeRedirect.js
const FRONTEND = new URL(process.env.FRONTEND_URL); // e.g. https://app.example.com/

function safeFrontendUrl(pathname = '/', params = {}) {
  const url = new URL(pathname, FRONTEND);     // preserves origin, resolves pathname
  for (const [k, v] of Object.entries(params)) {
    url.searchParams.set(k, String(v));
  }
  return url.toString();
}

module.exports = { safeFrontendUrl };
