import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, readdir, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve } from "node:path";

import { captureSourceSnapshot } from
  "./protected-inputs.mjs";

const sha256 = bytes => createHash("sha256").update(bytes).digest("hex");

export const WEB_ZIP_PASS237 = Object.freeze({
  schema: 1,
  issue: 19,
  preparationExecutorPass: 237,
  authorizationId: "issue19-native-windows-20261023",
  objectiveId: "web-entries",
  candidate: Object.freeze({
    origin: "https://linux-ai2.taile60a95.ts.net:8443",
    sha: "3105b01067ac415786d9c041cc922195c00c9cc4",
    version: "v0.92.0",
  }),
  fixture: Object.freeze({
    fixtureId: "issue19-web-zip-pass196",
    archiveFileName: "issue19-web-zip-pass196.zip",
    files: Object.freeze({
      "README.md": "653e3393a4e05b1b4d6fe2134e78ec4e7d3ef2ed932ad2633ee712a39be38e5d",
      "app.mjs": "acedfa3b1c5ae9669cc54862e48023051345c486d379bb95702fbe82b04d6f4b",
      "app.test.mjs": "1a398740f703630b966ce93c7d3b3eba53c68db3c9a1358d002357d102512ea9",
      "fixture.json": "39039701acf2b52b7507d5e27a47749902b0a5373d6f3547da675dc8d433abc7",
      "package.json": "ea38fe52b4c91091d85b8253900c59da8f7340847165d5d8aa19b7f4061d355b",
    }),
  }),
  deadlines: Object.freeze({
    totalMs: 600_000,
    fixtureMs: 20_000,
    launchMs: 40_000,
    launchReceiptMs: 35_000,
    debugMs: 25_000,
    pageMs: 30_000,
    pickerMs: 30_000,
    consentMs: 60_000,
    uploadMs: 60_000,
    analysisMs: 240_000,
    renderedMs: 60_000,
    cleanupMs: 75_000,
  }),
  maxima: Object.freeze({ pickerOpens: 1, fileSelections: 1, consentDescriptors: 1,
    uploads: 1, analyses: 1 }),
});

function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let bit = 0; bit < 8; bit += 1) crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function u16(value) { const bytes = Buffer.alloc(2); bytes.writeUInt16LE(value); return bytes; }
function u32(value) { const bytes = Buffer.alloc(4); bytes.writeUInt32LE(value >>> 0); return bytes; }

// Store-only ZIP with fixed metadata. The exact archive hash is therefore derived only from
// the reviewed names and source bytes; host time, locale and ZIP implementation cannot vary it.
export function buildDeterministicZip(entries) {
  const local = [];
  const central = [];
  let offset = 0;
  for (const [name, body] of [...entries].sort(([a], [b]) => a.localeCompare(b, "en"))) {
    assert.match(name, /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u);
    assert.ok(Buffer.isBuffer(body) && body.length <= 1024 * 1024);
    const fileName = Buffer.from(name, "utf8");
    const checksum = crc32(body);
    const header = Buffer.concat([u32(0x04034b50), u16(20), u16(0x0800), u16(0),
      u16(0), u16(0x0021), u32(checksum), u32(body.length), u32(body.length),
      u16(fileName.length), u16(0), fileName]);
    local.push(header, body);
    const directory = Buffer.concat([u32(0x02014b50), u16(0x0314), u16(20), u16(0x0800),
      u16(0), u16(0), u16(0x0021), u32(checksum), u32(body.length), u32(body.length),
      u16(fileName.length), u16(0), u16(0), u16(0), u16(0), u32(0x81a40000), u32(offset), fileName]);
    central.push(directory);
    offset += header.length + body.length;
  }
  const directoryBytes = Buffer.concat(central);
  return Buffer.concat([...local, directoryBytes, u32(0x06054b50), u16(0), u16(0),
    u16(entries.length), u16(entries.length), u32(directoryBytes.length), u32(offset), u16(0)]);
}

export async function captureExactFixture(root, expected = WEB_ZIP_PASS237.fixture.files) {
  assert.ok(isAbsolute(root));
  assert.equal(await realpath(root), root, "fixture-root-not-canonical");
  const names = (await readdir(root)).sort();
  assert.deepEqual(names, Object.keys(expected).sort(), "fixture-inventory-mismatch");
  const entries = [];
  const hashes = {};
  for (const name of names) {
    assert.ok(!name.includes("/") && name !== "." && name !== "..");
    const path = resolve(root, name);
    assert.equal(relative(root, path), name, "fixture-path-escape");
    const metadata = await lstat(path);
    assert.ok(metadata.isFile() && !metadata.isSymbolicLink(), "fixture-entry-not-regular");
    const snapshot = await captureSourceSnapshot(path, `fixture-${name}`, 1024 * 1024);
    assert.equal(snapshot.sha256, expected[name], `fixture-hash-${name}`);
    entries.push([name, snapshot.bytes]);
    hashes[name] = snapshot.sha256;
  }
  const archive = buildDeterministicZip(entries);
  return Object.freeze({ fixtureId: WEB_ZIP_PASS237.fixture.fixtureId, files: Object.freeze(hashes),
    sourceSetSha256: sha256(Buffer.from(JSON.stringify(hashes))), archive,
    archiveSha256: sha256(archive) });
}

