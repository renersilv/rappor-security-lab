import assert from "node:assert/strict";

export function assertRecoveryEligible(preparation, email, applications, scopes, now = Date.now()) {
  assert.equal(email, "lab-issue19-20261015@rappor.test");
  const authorizedAt = Date.parse(preparation.oauthReauthorizedAtUtc);
  assert.ok(Number.isFinite(authorizedAt) && now - authorizedAt > 8 * 60 * 60 * 1000);
  const existing = applications.find((item) => item.authorizationId === preparation.authorizationId);
  assert.ok(existing && existing.applicationName === "Codex" && !existing.revokedAt &&
    existing.isRevoked !== true && existing.status !== "revoked");
  const allowed = new Set([...scopes, "openid", "email", "profile", "offline_access"]);
  assert.ok(scopes.every((scope) => existing.scopes.includes(scope)));
  assert.ok(existing.scopes.every((scope) => allowed.has(scope)));
}
