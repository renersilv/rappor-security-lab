export const SUPABASE_URL = "https://rappor-lab.invalid";
export const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_RAPPOR_LAB_NON_FUNCTIONAL_PUBLIC_KEY";
export const SUPABASE_ANON_KEY = "RAPPOR_LAB_SYNTHETIC_SUPABASE_ANON_NON_FUNCTIONAL";
export const PUBLIC_SCRIPT_LIMIT = 6;

export const STATES = {
  vulnerable: {
    id: "vulnerable",
    securityHeaders: false,
    secureCookie: false,
    formMethod: "get",
    mixedContentUrl: "http://mixed-content.rappor-lab.invalid/pixel.svg",
    elevatedMarker: "RAPPOR_LAB_SYNTHETIC_SECRET_DO_NOT_USE_PUBLICVULN000001",
  },
  "partially-fixed": {
    id: "partially-fixed",
    securityHeaders: true,
    secureCookie: true,
    formMethod: "get",
    mixedContentUrl: "http://mixed-content.rappor-lab.invalid/pixel.svg",
    elevatedMarker: "RAPPOR_LAB_SYNTHETIC_SECRET_DO_NOT_USE_PUBLICPART000001",
  },
  fixed: {
    id: "fixed",
    securityHeaders: true,
    secureCookie: true,
    formMethod: "post",
    mixedContentUrl: "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg'/%3E",
    elevatedMarker: null,
  },
  reintroduced: {
    id: "reintroduced",
    securityHeaders: false,
    secureCookie: false,
    formMethod: "get",
    mixedContentUrl: "http://mixed-content.rappor-lab.invalid/reintroduced.svg",
    elevatedMarker: "RAPPOR_LAB_SYNTHETIC_SECRET_DO_NOT_USE_PUBLICREIN000001",
  },
};

export function getState(name = "fixed") {
  const state = STATES[name];
  if (!state) throw new Error(`Unknown RAPPOR_LAB_STATE: ${name}`);
  return state;
}

export function responseHeaders(state) {
  const headers = {
    "cache-control": "no-store",
    "x-powered-by": "Next.js",
    "x-rappor-lab-host-profile": "Vercel",
    "x-robots-tag": "noindex, nofollow, noarchive",
  };
  if (state.securityHeaders) {
    headers["content-security-policy"] = "default-src 'self'; script-src 'self'; style-src 'none'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'";
    headers["referrer-policy"] = "no-referrer";
    headers["x-content-type-options"] = "nosniff";
    headers["x-frame-options"] = "DENY";
  }
  return headers;
}

export function cookieOptions(state) {
  return state.secureCookie
    ? { httpOnly: true, path: "/", sameSite: "strict", secure: true }
    : { path: "/" };
}

export function renderPublicResource(state) {
  const configuration = {
    supabaseUrl: SUPABASE_URL,
    supabasePublishableKey: SUPABASE_PUBLISHABLE_KEY,
    supabaseAnonKey: SUPABASE_ANON_KEY,
    elevatedSyntheticMarker: state.elevatedMarker ?? "RAPPOR_LAB_NO_SECRET_FIXTURE",
  };
  return `globalThis.__RAPPOR_LAB_PUBLIC_CONFIG__ = Object.freeze(${JSON.stringify(configuration)});\n`;
}

export function renderDocument(state) {
  const mixedContentUrl = state.mixedContentUrl.replaceAll("&", "&amp;").replaceAll('"', "&quot;");
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="generator" content="Lovable">
    <meta name="robots" content="noindex,nofollow,noarchive">
    <title>Rappor Security controlled public target</title>
  </head>
  <body>
    <main data-framework="Next.js" data-generator="Lovable" data-host-profile="Vercel" data-lab-state="${state.id}">
      <h1>Controlled public security target</h1>
      <p>This page contains only deterministic synthetic fixtures.</p>
      <form action="/not-accepted" method="${state.formMethod}" data-lab-inert="true">
        <label for="lab-password">Synthetic password field</label>
        <input id="lab-password" type="password" autocomplete="off" disabled>
        <button type="button" disabled>Submission disabled</button>
      </form>
      <img alt="" data-lab-mixed-content="true" height="1" loading="lazy" src="${mixedContentUrl}" width="1">
      <output data-supabase-client="configured">Supabase client configured without network or persistence</output>
      <script src="/lab-resource.js"></script>
    </main>
  </body>
</html>`;
}

export function serializeCookie(state) {
  const options = cookieOptions(state);
  const attributes = ["rappor_lab_notice=synthetic"];
  if (options.path) attributes.push(`Path=${options.path}`);
  if (options.httpOnly) attributes.push("HttpOnly");
  if (options.secure) attributes.push("Secure");
  if (options.sameSite) attributes.push(`SameSite=${options.sameSite[0].toUpperCase()}${options.sameSite.slice(1)}`);
  return attributes.join("; ");
}
