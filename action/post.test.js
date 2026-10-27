'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { checkNotRunning, pmgRuns } = require('./post');

function withPID(pid, fn) {
  process.env.STATE_pid = pid;
  try {
    return fn();
  } finally {
    delete process.env.STATE_pid;
  }
}

test('pmgRuns is false for a missing process and for a process that is not pmg', () => {
  assert.strictEqual(pmgRuns('999999999'), false);
  assert.strictEqual(pmgRuns(String(process.pid)), false);
});

test('checkNotRunning', async (t) => {
  for (const [name, pid, failOnViolation, want] of [
    ['a stopped daemon fails the job with fail-on-violation', '999999999', true, { status: 1, lost: false }],
    ['a stopped daemon warns without fail-on-violation', '999999999', false, { status: 0, lost: false }],
    ['no saved pid fails the job with fail-on-violation', '', true, { status: 1, lost: false }],
  ]) {
    await t.test(name, () => assert.deepStrictEqual(withPID(pid, () => checkNotRunning(failOnViolation)), want));
  }
});
