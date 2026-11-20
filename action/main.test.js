'use strict';

const test = require('node:test');
const assert = require('node:assert');
const lib = require('./lib');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { checkInputs, enforceMode, failedPolicyFetch, refuseSecondProxy, resolveServerMode, runnerCannotEnforce } = require('./main');

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

test('failedPolicyFetch is true only for the policy exit status of enforce.sh', async (t) => {
  for (const [name, err, want] of [
    ['no cloud policy', new lib.ScriptError('enforce.sh', 3, '', ['Network']), true],
    ['a failed start', new lib.ScriptError('enforce.sh', 1, '', ['Network']), false],
    ['not a script error', new Error('x'), false],
  ]) {
    await t.test(name, () => assert.strictEqual(failedPolicyFetch(err), want));
  }
});

// fakePMG writes a pmg that prints status as pmg proxy status does.
function fakePMG(t, status) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pmg-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const bin = path.join(dir, 'pmg');
  fs.writeFileSync(bin, `#!/bin/sh\nprintf '%s\\n' '${status}'\n`, { mode: 0o755 });
  return bin;
}

test('refuseSecondProxy fails when a proxy of an earlier step runs', (t) => {
  const bin = fakePMG(t, 'PMG proxy: running (pid 42, addr 127.0.0.1:8888, ca /tmp/ca.pem)');
  assert.throws(() => refuseSecondProxy(bin), /pid 42\) already runs in this job/);
});

test('refuseSecondProxy passes when no proxy runs', (t) => {
  const bin = fakePMG(t, 'PMG proxy: not running');
  assert.doesNotThrow(() => refuseSecondProxy(bin));
});

test('config.sh exports the endpoint id of the repository', async (t) => {
  for (const [name, repository, endpointID, want] of [
    ['the default uses the form of pmg', 'octo-org/octo-repo', '', 'gh:octo-org/octo-repo'],
    ['the endpoint-id input overrides the default', 'octo-org/octo-repo', 'gha/octo-org/octo-repo', 'gha/octo-org/octo-repo'],
    ['no repository leaves the id to pmg', '', '', undefined],
  ]) {
    await t.test(name, (t) => {
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pmg-test-'));
      t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
      const envFile = path.join(dir, 'env');
      fs.writeFileSync(envFile, '');
      const res = spawnSync('sh', [path.join(lib.actionDir, 'config.sh')], {
        encoding: 'utf8',
        env: {
          PATH: process.env.PATH,
          HOME: dir,
          GITHUB_ENV: envFile,
          GH_REPOSITORY: repository,
          INPUT_CONFIG_FILE: '',
          IN_API_KEY: 'key',
          IN_TENANT_ID: 'tenant',
          IN_ENDPOINT_ID: endpointID,
          IN_SERVER_MODE: 'true',
          IN_PROXY_MODE: '',
          IN_PARANOID: '',
          IN_COOLDOWN_ENABLED: '',
          IN_COOLDOWN_DAYS: '',
          IN_SANDBOX: '',
          IN_SANDBOX_DRIVER: '',
          IN_VERBOSITY: '',
          IN_DISABLE_TELEMETRY: '',
          IN_SKIP_EVENT_LOGGING: '',
        },
      });
      assert.strictEqual(res.status, 0, res.stderr);
      const exported = new Map(lib.parseKeyValues(fs.readFileSync(envFile, 'utf8')));
      assert.strictEqual(exported.get('PMG_CLOUD_ENDPOINT_ID'), want);
    });
  }
});
