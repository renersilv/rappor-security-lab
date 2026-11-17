import assert from 'node:assert/strict';
import test from 'node:test';
import {
  buildWebZipStagePreparation,
  buildWebZipStageInvocation,
  buildWebZipStageCleanup,
} from '../source/powershell-stdin-transport.mjs';

// The Windows shell wrapper also consumes command-line space before PowerShell starts.
const maximumDirectCommandCharacters = 7600;
const sids = {
  observed: 'S-1-5-21-2980301157-3547504321-68234275-1000',
  maximumAccountSid: 'S-1-5-21-4294967295-4294967295-4294967295-4294967295',
};
for (const [name, sid] of Object.entries(sids)) {
  test(`native staging commands preserve shell wrapper margin for ${name}`, () => {
    const prepared = {
      requestSha256: 'a'.repeat(64),
      instruction: { desktop: { sid }, parentReserveMs: 15000, cleanupReserveMs: 90000 },
      package: { schema: 1, instructionBase64: '', instructionSha256: 'b'.repeat(64),
        archiveBase64: '', archiveSha256: 'c'.repeat(64), workerBase64: '', workerSha256: 'd'.repeat(64) },
    };
    const ticks = '3155378975999999999';
    const commands = {
      setup: buildWebZipStagePreparation(prepared).command,
      invocation: buildWebZipStageInvocation(prepared, ticks, 600000, 1800000000000).command,
      cleanup: buildWebZipStageCleanup(prepared, ticks),
    };
    for (const [stage, command] of Object.entries(commands)) {
      assert.ok(command.length <= maximumDirectCommandCharacters,
        `${stage} command length ${command.length} leaves insufficient shell wrapper margin`);
    }
  });
}
