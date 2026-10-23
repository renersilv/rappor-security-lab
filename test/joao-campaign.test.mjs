import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import test from 'node:test';

test('authorized native continuation preserves preparation, quota and delivery boundaries', () => {
  const result = spawnSync('python3', ['-B', 'ops/joao/test/campaign-tests.py'], {
    cwd: new URL('..', import.meta.url), encoding: 'utf8', timeout: 30000,
  });
  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
});
