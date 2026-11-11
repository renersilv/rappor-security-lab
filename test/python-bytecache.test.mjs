import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFile, mkdtemp, mkdir, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("real Python bytecache is ignored while unexpected executable source remains dirty", async t => {
  const root = await mkdtemp(join(tmpdir(), "joao-bytecache-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const git = (...args) => execFileSync("git", ["-C", root, ...args], { encoding: "utf8" });
  git("init", "--quiet");
  await copyFile(new URL("../.gitignore", import.meta.url), join(root, ".gitignore"));
  const directory = join(root, "ops/joao");
  await mkdir(directory, { recursive: true });
  const source = join(directory, "campaign-review.py");
  await writeFile(source, '"""Synthetic bytecode regression fixture."""\nVALUE = 1\n');
  git("add", ".gitignore", "ops/joao/campaign-review.py");
  const before = git("status", "--porcelain", "--untracked-files=all");
  execFileSync("python3", ["-I", "-c", "import py_compile,sys;py_compile.compile(sys.argv[1],doraise=True)", source]);
  assert.equal((await readdir(join(directory, "__pycache__"))).some(name => name.endsWith(".pyc")), true);
  assert.equal(git("status", "--porcelain", "--untracked-files=all"), before);
  await writeFile(join(directory, "unexpected.py"), "raise RuntimeError('unexpected source')\n");
  assert.match(git("status", "--porcelain", "--untracked-files=all"), /\?\? ops\/joao\/unexpected\.py/u);
  await writeFile(source, "VALUE = 2\n");
  assert.match(git("status", "--porcelain", "--untracked-files=all"), /AM ops\/joao\/campaign-review\.py/u);
});
