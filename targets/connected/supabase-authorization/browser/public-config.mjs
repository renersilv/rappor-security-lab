const PROJECT_URL = /^https:\/\/[a-z0-9-]+\.supabase\.co$/;

export function createPublicSupabaseConfig({ url, publishableKey }) {
  if (typeof url !== "string" || !PROJECT_URL.test(url)) {
    throw new Error("a standard HTTPS Supabase project URL is required");
  }
  if (typeof publishableKey !== "string" || !publishableKey.startsWith("sb_publishable_")) {
    throw new Error("a Supabase publishable key is required");
  }
  return Object.freeze({ url, publishableKey });
}
