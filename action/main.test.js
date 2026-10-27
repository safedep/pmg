'use strict';

const test = require('node:test');
const assert = require('node:assert');
const lib = require('./lib');
const { checkInputs, enforceMode, resolveServerMode, runnerCannotEnforce } = require('./main');

// withEnv sets the variables for one call and restores them after it.
function withEnv(vars, fn) {
  const saved = {};
  for (const [name, value] of Object.entries(vars)) {
    saved[name] = process.env[name];
    process.env[name] = value;
  }
  try {
    return fn();
  } finally {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}

test('resolveServerMode', async (t) => {
  for (const [name, env, profile, want] of [
    ['server mode by default', {}, '', true],
    ['sandbox keeps the shims', { INPUT_SANDBOX: 'true' }, '', false],
    ['server-mode false selects the shims', { 'INPUT_SERVER-MODE': 'false' }, '', false],
    ['server-mode true beats sandbox', { 'INPUT_SERVER-MODE': 'true', INPUT_SANDBOX: 'true' }, '', true],
    ['a network profile turns server mode on', { INPUT_SANDBOX: 'true' }, 'github-actions', true],
  ]) {
    await t.test(name, () => assert.strictEqual(withEnv(env, () => resolveServerMode(profile)), want));
  }
});

test('resolveServerMode fails on a conflict and on a typo', async (t) => {
  await t.test('network profile with server-mode false', () =>
    assert.throws(() => withEnv({ 'INPUT_SERVER-MODE': 'false' }, () => resolveServerMode('ci.yml')), /network-profile needs server mode/));
  await t.test('typo', () =>
    assert.throws(() => withEnv({ 'INPUT_SERVER-MODE': 'ture' }, () => resolveServerMode('')), /server-mode must be one of/));
});

test('checkInputs fails when enforce true meets shim mode', () => {
  assert.throws(() => checkInputs(false, 'true'), /enforce true needs server mode/);
  assert.doesNotThrow(() => checkInputs(true, 'true'));
  assert.doesNotThrow(() => checkInputs(false, 'auto'));
});

test('enforceMode', async (t) => {
  const hosted = { RUNNER_ENVIRONMENT: 'github-hosted' };
  for (const [name, env, enforce, jobContainer, want] of [
    ['true requires enforcement', hosted, 'true', true, 'required'],
    ['false turns it off', hosted, 'false', false, 'off'],
    ['auto in a job container', hosted, 'auto', true, 'off'],
    ['auto with expose-to-job-network', { ...hosted, 'INPUT_EXPOSE-TO-JOB-NETWORK': 'true' }, 'auto', false, 'off'],
    ['auto on a self-hosted runner', { RUNNER_ENVIRONMENT: 'self-hosted' }, 'auto', false, 'off'],
    ['auto without a runner environment', { RUNNER_ENVIRONMENT: '' }, 'auto', false, 'off'],
  ]) {
    await t.test(name, () => assert.strictEqual(withEnv(env, () => enforceMode(enforce, jobContainer)), want));
  }
});

test('enforceMode fails when auto cannot enforce and an enforce input is set', () => {
  assert.throws(
    () => withEnv({ RUNNER_ENVIRONMENT: 'github-hosted', 'INPUT_ENFORCE-NAMESPACES': 'redirect' }, () => enforceMode('auto', true)),
    /enforce-\* inputs need kernel enforcement, .* job container/,
  );
});

test('runnerCannotEnforce is true only for a runner error code', async (t) => {
  for (const [name, err, want] of [
    ['missing kernel support', new lib.ScriptError('enforce.sh', 1, '', ['EnforceRequirements']), true],
    ['unsupported platform', new lib.ScriptError('enforce.sh', 1, '', ['UnsupportedPlatform']), true],
    ['a policy error', new lib.ScriptError('enforce.sh', 1, '', ['InvalidArgument']), false],
    ['no code', new lib.ScriptError('enforce.sh', 1), false],
    ['not a script error', new Error('x'), false],
  ]) {
    await t.test(name, () => assert.strictEqual(runnerCannotEnforce(err), want));
  }
});
