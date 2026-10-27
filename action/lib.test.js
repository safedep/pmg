'use strict';

const test = require('node:test');
const assert = require('node:assert');
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

test('errorCodes reads the code of each pmg error line', () => {
  const stderr = '✓ CA already installed\n\x1b[41m EnforceRequirements \x1b[0m  this host cannot enforce\n → load the BTF\n';
  assert.deepStrictEqual(lib.errorCodes(stderr), ['EnforceRequirements']);
  assert.deepStrictEqual(lib.errorCodes(' InvalidArgument   the enforce policy is not valid\n'), ['InvalidArgument']);
  assert.deepStrictEqual(lib.errorCodes('Network: 2 destination(s) observed\n'), []);
});
