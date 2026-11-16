import assert from "node:assert/strict";
import test from "node:test";

import { normalizeUserLabel } from "./app.mjs";

test("normalizes whitespace without external effects", () => {
  assert.equal(normalizeUserLabel("  laboratory   sample  "), "laboratory sample");
});

test("rejects non-string input", () => {
  assert.throws(() => normalizeUserLabel(null), TypeError);
});
