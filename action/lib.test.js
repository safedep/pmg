'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const lib = require('./lib');

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

function capturePrint(t, text) {
  const writes = [];
  t.mock.method(process.stdout, 'write', (chunk) => {
    writes.push(String(chunk));
    return true;
  });
  lib.printUntrusted(text);
  t.mock.restoreAll();
  return writes.join('');
}

test('printUntrusted stops the workflow commands while it prints the text', async (t) => {
  const payloads = [
    'no rule\n::warning::injected\n',
    'no rule ##[add-mask]acme\n',
    'no rule\r::add-mask::acme\n',
    'no rule\n  \x1b[31m::add-mask::x\x1b[0m',
  ];
  for (const text of payloads) {
    await t.test(JSON.stringify(text), (t) => {
      const out = capturePrint(t, text);
      const match = /^::stop-commands::([0-9a-f-]{36})\n([\s\S]*)::\1::\n$/.exec(out);
      assert.ok(match, out);
      assert.strictEqual(match[2], text.endsWith('\n') ? text : `${text}\n`);
    });
  }
});

test('printUntrusted uses a new token for each print', (t) => {
  const token = (out) => /^::stop-commands::(\S+)\n/.exec(out)[1];
  assert.notStrictEqual(token(capturePrint(t, 'a\n')), token(capturePrint(t, 'a\n')));
});

test('printUntrusted writes the resume line when the print throws', (t) => {
  const writes = [];
  let calls = 0;
  t.mock.method(process.stdout, 'write', (chunk) => {
    calls += 1;
    if (calls === 2) {
      throw new Error('EPIPE');
    }
    writes.push(String(chunk));
    return true;
  });
  assert.throws(() => lib.printUntrusted('text\n'), /EPIPE/);
  t.mock.restoreAll();
  const token = /^::stop-commands::(\S+)\n/.exec(writes[0])[1];
  assert.strictEqual(writes[1], `::${token}::\n`);
});

test('errorLines reads the code and the message of each pmg error line', () => {
  const stderr = '✓ CA already installed\n\x1b[41m EnforceRequirements \x1b[0m  this host cannot enforce\n → load the BTF\n';
  assert.deepStrictEqual(lib.errorLines(stderr), [{ code: 'EnforceRequirements', message: 'this host cannot enforce' }]);
  assert.deepStrictEqual(lib.errorCodes(stderr), ['EnforceRequirements']);
  assert.deepStrictEqual(lib.errorCodes(' InvalidArgument   the enforce policy is not valid\n'), ['InvalidArgument']);
  assert.deepStrictEqual(lib.errorCodes('Network: 2 destination(s) observed\n'), []);
  assert.deepStrictEqual(lib.errorLines(' WorkloadExchangeRefused   refused (no rule\r::add-mask::acme)\n'), [
    { code: 'WorkloadExchangeRefused', message: 'refused (no rule\r::add-mask::acme)' },
  ]);
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
