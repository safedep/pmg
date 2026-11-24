'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const lib = require('./lib');
const { tempDir, withEnv } = require('./testenv');

test('parseKeyValues reads both forms of the runner files', () => {
  const text = 'A=1\r\nB=x=y\nC<<EOF\nline 1\r\nline 2\nEOF\n\nD=\n';
  assert.deepStrictEqual(lib.parseKeyValues(text), [
    ['A', '1'],
    ['B', 'x=y'],
    ['C', 'line 1\nline 2'],
    ['D', ''],
  ]);
});

test('parseKeyValues does not read a value with << as a heredoc', () => {
  assert.deepStrictEqual(lib.parseKeyValues('A=b<<c\n'), [['A', 'b<<c']]);
});

test('isProfilePath matches executor.IsProfilePath', () => {
  for (const [ref, want] of [
    ['github-actions', false],
    ['npm-restrictive', false],
    ['.pmg/ci.yml', true],
    ['ci.yaml', true],
    ['profiles/ci', true],
  ]) {
    assert.strictEqual(lib.isProfilePath(ref), want, ref);
  }
});

test('childEnv drops the job tokens', () => {
  process.env.ACTIONS_RUNTIME_TOKEN = 'secret';
  process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN = 'secret';
  try {
    const env = lib.childEnv({ PMG_X: '1' });
    assert.strictEqual(env.ACTIONS_RUNTIME_TOKEN, undefined);
    assert.strictEqual(env.ACTIONS_ID_TOKEN_REQUEST_TOKEN, undefined);
    assert.strictEqual(env.PMG_X, '1');
    assert.strictEqual(process.env.ACTIONS_RUNTIME_TOKEN, 'secret');
  } finally {
    delete process.env.ACTIONS_RUNTIME_TOKEN;
    delete process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  }
});

test('lastLines keeps the cause and drops colors and workflow commands', () => {
  const stderr = 'starting\n\x1b[31m InvalidArgument \x1b[0m bad prefix\n → fix the CIDR\n::error::x\n\n';
  assert.strictEqual(lib.lastLines(stderr, 2), 'InvalidArgument  bad prefix → fix the CIDR');
});

test('errorCodes reads the code of each pmg error line', () => {
  const stderr = '✓ CA already installed\n\x1b[41m EnforceRequirements \x1b[0m  this host cannot enforce\n → load the BTF\n';
  assert.deepStrictEqual(lib.errorCodes(stderr), ['EnforceRequirements']);
  assert.deepStrictEqual(lib.errorCodes(' InvalidArgument   the enforce policy is not valid\n'), ['InvalidArgument']);
  assert.deepStrictEqual(lib.errorCodes('Network: 2 destination(s) observed\n'), []);
});

test('runPMG runs a helper call with SafeDep Cloud off', (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pmg-helper-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const bin = path.join(dir, 'pmg');
  fs.writeFileSync(bin, '#!/bin/sh\nenv\n', { mode: 0o755 });

  const saved = process.env.PMG_CLOUD_ENABLED;
  process.env.PMG_CLOUD_ENABLED = 'true';
  try {
    const res = lib.runPMG(bin, ['version'], { capture: true });
    assert.match(res.stdout, /^PMG_CLOUD_ENABLED=false$/m);
    assert.match(lib.helperEnv().PMG_CLOUD_ENABLED, /^false$/);
  } finally {
    if (saved === undefined) {
      delete process.env.PMG_CLOUD_ENABLED;
    } else {
      process.env.PMG_CLOUD_ENABLED = saved;
    }
  }
});

test('runPMG under sudo passes no directory of the job', async (t) => {
  const dir = tempDir(t);
  fs.writeFileSync(path.join(dir, 'sudo'), '#!/bin/sh\nenv\n', { mode: 0o755 });
  const env = { PATH: `${dir}${path.delimiter}${process.env.PATH}`, PMG_CONFIG_DIR: '/job/config', PMG_STATE_DIR: '/job/state' };
  for (const [name, configDir, want] of [
    ['no daemon directory', '', null],
    ['the daemon directory', '/daemon/config', /^PMG_CONFIG_DIR=\/daemon\/config$/m],
  ]) {
    await t.test(name, () => {
      const out = withEnv(env, () => lib.runPMG('pmg', ['version'], { sudo: true, configDir, capture: true }).stdout);
      assert.doesNotMatch(out, /^PMG_(CONFIG|STATE)_DIR=\/job\//m);
      if (want) {
        assert.match(out, want);
      }
    });
  }
});
