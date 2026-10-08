import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';
import test from 'node:test';
import { isReparsePoint, loadReviewSource, resolveReviewSourcePath } from '../src/local-mcp/source-contract.mjs';

const fixtureRoot = resolve('tests/fixtures/openrouter-review');
const allowedRoot = join(fixtureRoot, 'allowed');
const allowedPath = join(allowedRoot, 'spec.md');
const outsidePath = join(fixtureRoot, 'outside', 'secret.md');
const policy = Object.freeze({ allowedRoots: [allowedRoot], maxSourceBytes: 1_024 });

test('raw text is normalized and hash-stable without persistence', async () => {
  const raw = ['a', 'b', 'c'].join('\r\n');
  const source = await loadReviewSource({ source_text: raw }, policy);

  assert.deepEqual(source, {
    text: 'a\nb\nc',
    sourceSha256: createHash('sha256').update('a\nb\nc', 'utf8').digest('hex'),
    sourceLabel: 'inline',
  });
});

test('standalone CR is normalized to LF without other rewriting', async () => {
  const raw = ['left', 'right'].join('\r');
  const source = await loadReviewSource({ source_text: raw }, policy);
  assert.equal(source.text, 'left\nright');
  assert.equal(source.sourceSha256, createHash('sha256').update('left\nright', 'utf8').digest('hex'));
});

test('full raw source sentinel preserves every non-newline byte while normalizing all line endings', async () => {
  const raw = 'SOURCE-SENTINEL-7f6bcda1\r\n  preserve spaces\rterminal';
  const normalized = 'SOURCE-SENTINEL-7f6bcda1\n  preserve spaces\nterminal';
  const source = await loadReviewSource({ source_text: raw }, policy);
  assert.equal(source.text, normalized);
  assert.equal(source.sourceSha256, createHash('sha256').update(normalized, 'utf8').digest('hex'));
});

test('exactly one source form is required', async () => {
  await assert.rejects(() => loadReviewSource({}, policy), /exactly one/i);
  await assert.rejects(() => loadReviewSource({ source_text: 'x', source_path: allowedPath }, policy), /exactly one/i);
});

test('source paths must be absolute and inside an allowed root', async () => {
  assert.equal(isAbsolute(allowedPath), true);
  await assert.rejects(() => loadReviewSource({ source_path: 'tests/fixtures/openrouter-review/allowed/spec.md' }, policy), /absolute/i);
  await assert.rejects(() => loadReviewSource({ source_path: outsidePath }, policy), /allowed root/i);
});

test('an allowed regular absolute source path is read, normalized, and hashed for trusted operators', async () => {
  const fixtureBytes = await readFile(allowedPath);
  const expectedText = fixtureBytes.toString('utf8').replace(/\r\n|\r/g, '\n');
  const source = await loadReviewSource({ source_path: allowedPath }, policy);
  assert.deepEqual(source, {
    text: expectedText,
    sourceSha256: createHash('sha256').update(expectedText, 'utf8').digest('hex'),
    sourceLabel: allowedPath,
  });
});

test('reparse-point guard identifies symbolic-link lstat results', () => {
  assert.equal(isReparsePoint({ isSymbolicLink: () => true }), true);
  assert.equal(isReparsePoint({ isSymbolicLink: () => false }), false);
});

test('Windows-compatible junction guard rejects an intermediate reparse directory when supported', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('NTFS junction coverage is Windows-only');
    return;
  }
  const root = await mkdtemp(join(tmpdir(), 'openrouter-review-junction-'));
  const allowed = join(root, 'allowed');
  const target = join(root, 'target');
  const junction = join(allowed, 'intermediate');
  const candidate = join(junction, 'spec.md');
  try {
    await mkdir(allowed);
    await mkdir(target);
    await writeFile(join(target, 'spec.md'), 'ordinary source');
    try {
      await symlink(target, junction, 'junction');
    } catch (error) {
      t.skip(`junctions unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.equal((await lstat(junction)).isSymbolicLink(), true);
    await assert.rejects(() => loadReviewSource({ source_path: candidate }, { allowedRoots: [allowed], maxSourceBytes: 1_024 }), /reparse point/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('Windows-compatible junction guard rejects a reparse-point allowed root when supported', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('NTFS junction coverage is Windows-only');
    return;
  }
  const root = await mkdtemp(join(tmpdir(), 'openrouter-review-root-junction-'));
  const target = join(root, 'target');
  const allowed = join(root, 'allowed-root');
  const candidate = join(allowed, 'spec.md');
  try {
    await mkdir(target);
    await writeFile(join(target, 'spec.md'), 'ordinary source');
    try {
      await symlink(target, allowed, 'junction');
    } catch (error) {
      t.skip(`junctions unavailable: ${error.code ?? error.message}`);
      return;
    }
    assert.equal((await lstat(allowed)).isSymbolicLink(), true);
    await assert.rejects(() => loadReviewSource({ source_path: candidate }, { allowedRoots: [allowed], maxSourceBytes: 1_024 }), /reparse point/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('regular-file symbolic links are rejected when the platform permits creating them', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'openrouter-review-file-link-'));
  const allowed = join(root, 'allowed');
  const target = join(root, 'target.md');
  const link = join(allowed, 'linked.md');
  try {
    await mkdir(allowed);
    await writeFile(target, 'ordinary source');
    try {
      await symlink(target, link, 'file');
    } catch (error) {
      t.skip(`file symbolic links unavailable: ${error.code ?? error.message}`);
      return;
    }
    await assert.rejects(() => loadReviewSource({ source_path: link }, { allowedRoots: [allowed], maxSourceBytes: 1_024 }), /reparse point/i);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('path byte limit is checked before UTF-8 decoding', async () => {
  const dir = await mkdtemp(join(allowedRoot, 'source-contract-'));
  const invalidUtf8 = join(dir, 'too-large-invalid.md');
  try {
    await writeFile(invalidUtf8, Buffer.from([0xff, 0x62]));
    await assert.rejects(
      () => loadReviewSource(
        { source_path: invalidUtf8 },
        { ...policy, maxSourceBytes: 1 },
      ),
      /byte limit/i,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('path sources preserve a leading UTF-8 BOM while normalizing CRLF', async () => {
  const dir = await mkdtemp(join(allowedRoot, 'source-contract-bom-'));
  const bomPath = join(dir, 'bom.md');
  try {
    await writeFile(bomPath, Buffer.from([0xef, 0xbb, 0xbf, 0x61, 0x0d, 0x0a, 0x62]));
    const source = await loadReviewSource({ source_path: bomPath }, policy);
    assert.equal(source.text, '\ufeffa\nb');
    assert.equal(source.sourceSha256, createHash('sha256').update('\ufeffa\nb', 'utf8').digest('hex'));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('source loading never invokes a supplied persistence writer with the source sentinel', async () => {
  const writes = [];
  const fileSystem = {
    lstat,
    readFile,
    realpath: (path) => import('node:fs/promises').then(({ realpath }) => realpath(path)),
    writeFile: (...args) => writes.push(args),
  };
  const source = await loadReviewSource({ source_path: allowedPath }, policy, { fileSystem });
  assert.match(source.text, /SOURCE-SENTINEL-7f6bcda1/);
  assert.deepEqual(writes, []);
});

test('path-only resolution returns canonical metadata without reading source content', async () => {
  let readCalls = 0;
  const resolvedSource = await resolveReviewSourcePath(
    { sourcePath: allowedPath, allowedRoots: [allowedRoot], maxSourceBytes: 1_024 },
    {
      fileSystem: {
        lstat,
        realpath,
        readFile: async () => {
          readCalls += 1;
          throw new Error('READ-FILE-SENTINEL');
        },
      },
    },
  );
  const canonicalPath = await realpath(allowedPath);
  const canonicalRoot = await realpath(allowedRoot);
  const fixtureBytes = await readFile(allowedPath);
  assert.deepEqual(resolvedSource, {
    canonicalPath,
    canonicalRoot,
    byteLength: fixtureBytes.byteLength,
  });
  assert.equal(readCalls, 0);
});

test('path-only resolution rejects sibling-prefix escape and invokes no content reader', async () => {
  const root = await mkdtemp(join(tmpdir(), 'openrouter-review-prefix-'));
  const allowed = join(root, 'project');
  const sibling = join(root, 'project-private');
  const candidate = join(sibling, 'secret.md');
  let readCalls = 0;
  try {
    await mkdir(allowed);
    await mkdir(sibling);
    await writeFile(candidate, 'SOURCE-SIBLING-SENTINEL');
    await assert.rejects(
      () => resolveReviewSourcePath(
        { sourcePath: candidate, allowedRoots: [allowed], maxSourceBytes: 1_024 },
        {
          fileSystem: {
            lstat,
            realpath,
            readFile: async () => {
              readCalls += 1;
              throw new Error('READ-FILE-SENTINEL');
            },
          },
        },
      ),
      /allowed root/i,
    );
    assert.equal(readCalls, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('path-only resolution rejects accessor-backed input before filesystem access', async () => {
  let getterReads = 0;
  let fileSystemCalls = 0;
  const input = { allowedRoots: [allowedRoot], maxSourceBytes: 1_024 };
  Object.defineProperty(input, 'sourcePath', {
    enumerable: true,
    get() {
      getterReads += 1;
      throw new Error('SOURCE-PATH-ACCESSOR-SENTINEL');
    },
  });
  const never = async () => {
    fileSystemCalls += 1;
    throw new Error('FILESYSTEM-SENTINEL');
  };
  await assert.rejects(
    () => resolveReviewSourcePath(input, { fileSystem: { lstat: never, realpath: never, readFile: never } }),
    TypeError,
  );
  assert.equal(getterReads, 0);
  assert.equal(fileSystemCalls, 0);
});

test('path-only resolution follows filesystem case handling and reports the canonical root', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('case-insensitive canonical path coverage is Windows-only');
    return;
  }
  const result = await resolveReviewSourcePath({
    sourcePath: allowedPath.toUpperCase(),
    allowedRoots: [allowedRoot.toUpperCase()],
    maxSourceBytes: 1_024,
  });
  assert.equal(result.canonicalPath, await realpath(allowedPath));
  assert.equal(result.canonicalRoot, await realpath(allowedRoot));
});
