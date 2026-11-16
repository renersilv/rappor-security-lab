export function normalizeUserLabel(value) {
  if (typeof value !== "string") {
    throw new TypeError("value must be a string");
  }
  return value.trim().replace(/\s+/gu, " ").slice(0, 80);
}
