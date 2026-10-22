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
