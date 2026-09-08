import assert from "node:assert/strict";
import test from "node:test";

import { verifySupabaseConnectedReport } from "../src/verify-supabase-connected-report.mjs";

test("dated connected Supabase report is complete, reproducible and sanitized", async () => {
  assert.deepEqual(await verifySupabaseConnectedReport(), {
    recordPath: "observations/supabase-connected/2026-09-08T184515Z.json",
    status: "completed",
    verdict: "passed",
    states: 4,
    cases: 16,
    reset: true,
  });
});
