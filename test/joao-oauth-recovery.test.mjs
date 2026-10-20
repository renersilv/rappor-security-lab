import assert from "node:assert/strict";
import test from "node:test";
import { assertRecoveryEligible } from "../ops/joao/oauth-recovery-policy.mjs";

const now = Date.parse("2026-10-20T15:00:00Z");
const preparation = { authorizationId: "synthetic-grant", oauthReauthorizedAtUtc: "2026-10-20T06:00:00Z" };
const scopes = ["product.read", "computer.manage"];
const application = { authorizationId: "synthetic-grant", applicationName: "Codex", scopes };
const email = "lab-issue19-20261015@rappor.test";

test("only an expired existing isolated grant is eligible for bounded recovery", () => {
  assert.doesNotThrow(() => assertRecoveryEligible(preparation, email, [application], scopes, now));
  for (const authorizationAt of ["2026-10-20T10:00:00Z", "invalid", "2026-10-21T00:00:00Z"]) {
    assert.throws(() => assertRecoveryEligible({ ...preparation, oauthReauthorizedAtUtc: authorizationAt },
      email, [application], scopes, now));
  }
});

test("revocation, missing authorization and changed account or scopes fail closed", () => {
  for (const applications of [[], [{ ...application, revokedAt: "2026-10-20T14:00:00Z" }],
    [{ ...application, isRevoked: true }], [{ ...application, status: "revoked" }],
    [{ ...application, scopes: ["product.read"] }],
    [{ ...application, scopes: [...scopes, "integration.manage"] }]]) {
    assert.throws(() => assertRecoveryEligible(preparation, email, applications, scopes, now));
  }
  assert.throws(() => assertRecoveryEligible(preparation, "owner@example.invalid", [application], scopes, now));
});
