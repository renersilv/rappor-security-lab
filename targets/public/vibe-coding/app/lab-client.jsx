"use client";

import { createClient } from "@supabase/supabase-js";
import { useMemo } from "react";

import { SUPABASE_PUBLISHABLE_KEY, SUPABASE_URL } from "../lib/states.mjs";

const blockedFetch = async () => {
  throw new Error("Network access is disabled for the laboratory Supabase client fixture.");
};

export default function LabClient() {
  const client = useMemo(
    () => createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
      auth: {
        autoRefreshToken: false,
        detectSessionInUrl: false,
        persistSession: false,
      },
      global: { fetch: blockedFetch },
    }),
    [],
  );

  return (
    <output data-supabase-client={client ? "configured" : "unavailable"}>
      Supabase client configured without network or persistence
    </output>
  );
}
