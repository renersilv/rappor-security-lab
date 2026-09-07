export const SUPABASE_URL = "https://rappor-lab.invalid";
export const SUPABASE_PUBLISHABLE_KEY = "sb_publishable_RAPPOR_LAB_NON_FUNCTIONAL_PUBLIC_KEY";
export const SUPABASE_ANON_KEY = "RAPPOR_LAB_SYNTHETIC_SUPABASE_ANON_NON_FUNCTIONAL";

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

export function getState(name = process.env.RAPPOR_LAB_STATE ?? "fixed") {
  const state = STATES[name];
  if (!state) throw new Error(`Unknown RAPPOR_LAB_STATE: ${name}`);
  return state;
}

export function responseHeaders(state, nonce = "RAPPOR_LAB_LOCAL_NONCE") {
  const headers = {
    "cache-control": "no-store",
    "x-powered-by": "Next.js",
    "x-rappor-lab-host-profile": "Vercel",
    "x-robots-tag": "noindex, nofollow, noarchive",
  };
  if (state.securityHeaders) {
    headers["content-security-policy"] = `default-src 'self'; script-src 'self' 'nonce-${nonce}' 'strict-dynamic'; style-src 'self' 'nonce-${nonce}'; img-src 'self' data:; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`;
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
