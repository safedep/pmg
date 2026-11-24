'use strict';

const test = require('node:test');
const assert = require('node:assert');
const lib = require('./lib');
const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const { tempDir, withEnv } = require('./testenv');
const { checkInputs, enforceMode, enforcedElsewhere, exportJobDirs, failedPolicyFetch, refuseSecondProxy, resolveServerMode, runnerCannotEnforce } = require('./main');

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

test('enforcedElsewhere is true only for a daemon that already enforces', async (t) => {
  for (const [name, err, want] of [
    ['another daemon enforces', new lib.ScriptError('enforce.sh', 1, '', ['EnforceAlreadyActive']), true],
    ['missing kernel support', new lib.ScriptError('enforce.sh', 1, '', ['EnforceRequirements']), false],
    ['not a script error', new Error('x'), false],
  ]) {
    await t.test(name, () => assert.strictEqual(enforcedElsewhere(err), want));
  }
});

test('exportJobDirs', async (t) => {
  // runExport runs exportJobDirs in a fresh RUNNER_TEMP and returns the
  // directories, the exported variables and RUNNER_TEMP.
  const runExport = (t, jobContainer, configDir, configFile = '') => {
    const tmp = tempDir(t);
    const envFile = path.join(tmp, 'env');
    fs.writeFileSync(envFile, '');
    const dirs = withEnv({ RUNNER_TEMP: tmp, GITHUB_ENV: envFile, PMG_CONFIG_DIR: configDir, PMG_STATE_DIR: undefined }, () => {
      exportJobDirs(jobContainer, configFile);
      return { config: process.env.PMG_CONFIG_DIR, state: process.env.PMG_STATE_DIR };
    });
    return { dirs, exported: Object.fromEntries(lib.parseKeyValues(fs.readFileSync(envFile, 'utf8'))), tmp };
  };

  await t.test('puts config and state under RUNNER_TEMP', (t) => {
    const { dirs, exported, tmp } = runExport(t, false, undefined);
    assert.deepStrictEqual(dirs, { config: path.join(tmp, 'pmg', 'config'), state: path.join(tmp, 'pmg', 'state') });
    assert.deepStrictEqual(exported, { PMG_CONFIG_DIR: dirs.config, PMG_STATE_DIR: dirs.state });
    assert.ok(fs.statSync(dirs.config).isDirectory());
    assert.ok(fs.statSync(dirs.state).isDirectory());
  });

  await t.test('keeps a directory that the workflow sets', (t) => {
    const own = path.join(tempDir(t), 'own');
    const { dirs, exported } = runExport(t, false, own);
    assert.strictEqual(dirs.config, own);
    assert.ok(fs.statSync(own).isDirectory());
    assert.deepStrictEqual(Object.keys(exported), ['PMG_STATE_DIR']);
  });

  await t.test('replaces a config directory that the workflow sets when the job sets config-file', (t) => {
    const own = path.join(tempDir(t), 'own');
    const { dirs, exported, tmp } = runExport(t, false, own, 'pmg.yml');
    assert.strictEqual(dirs.config, path.join(tmp, 'pmg', 'config'));
    assert.strictEqual(exported.PMG_CONFIG_DIR, dirs.config);
  });

  await t.test('changes nothing in a job container', (t) => {
    const { dirs, exported } = runExport(t, true, undefined);
    assert.deepStrictEqual(dirs, { config: undefined, state: undefined });
    assert.deepStrictEqual(exported, {});
  });
});

// fakePMG writes a pmg that prints status as pmg proxy status does.
function fakePMG(t, status) {
  const bin = path.join(tempDir(t), 'pmg');
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

// runConfigScript runs config.sh in dir with the IN_* inputs empty, then env,
// and returns the variables that it exported.
function runConfigScript(dir, env) {
  const envFile = path.join(dir, 'env');
  fs.writeFileSync(envFile, '');
  const inputs = ['IN_API_KEY', 'IN_TENANT_ID', 'IN_ENDPOINT_ID', 'IN_PROXY_MODE', 'IN_PARANOID', 'IN_COOLDOWN_ENABLED',
    'IN_COOLDOWN_DAYS', 'IN_SANDBOX', 'IN_SANDBOX_DRIVER', 'IN_VERBOSITY', 'IN_DISABLE_TELEMETRY', 'IN_SKIP_EVENT_LOGGING'];
  const res = spawnSync('sh', [path.join(lib.actionDir, 'config.sh')], {
    encoding: 'utf8',
    env: {
      ...Object.fromEntries(inputs.map((name) => [name, ''])),
      PATH: process.env.PATH,
      HOME: dir,
      GITHUB_ENV: envFile,
      GITHUB_WORKSPACE: dir,
      GH_REPOSITORY: '',
      INPUT_CONFIG_FILE: '',
      IN_SERVER_MODE: 'true',
      ...env,
    },
  });
  assert.strictEqual(res.status, 0, res.stderr);
  return new Map(lib.parseKeyValues(fs.readFileSync(envFile, 'utf8')));
}

test('config.sh exports the endpoint id of the repository', async (t) => {
  for (const [name, repository, endpointID, want] of [
    ['the default uses the form of pmg', 'octo-org/octo-repo', '', 'gh:octo-org/octo-repo'],
    ['the endpoint-id input overrides the default', 'octo-org/octo-repo', 'gha/octo-org/octo-repo', 'gha/octo-org/octo-repo'],
    ['no repository leaves the id to pmg', '', '', undefined],
  ]) {
    await t.test(name, (t) => {
      const exported = runConfigScript(tempDir(t), {
        GH_REPOSITORY: repository,
        IN_API_KEY: 'key',
        IN_TENANT_ID: 'tenant',
        IN_ENDPOINT_ID: endpointID,
      });
      assert.strictEqual(exported.get('PMG_CLOUD_ENDPOINT_ID'), want);
    });
  }
});

test('config.sh stages config-file in PMG_CONFIG_DIR', async (t) => {
  for (const [name, configDir, want] of [
    ['the config directory of the job', 'job', 'job/config.yml'],
    ['the default without PMG_CONFIG_DIR', '', '.config/safedep/pmg/config.yml'],
  ]) {
    await t.test(name, (t) => {
      const dir = tempDir(t);
      fs.writeFileSync(path.join(dir, 'pmg.yml'), 'paranoid: true\n');
      runConfigScript(dir, { INPUT_CONFIG_FILE: 'pmg.yml', PMG_CONFIG_DIR: configDir && path.join(dir, configDir) });
      assert.strictEqual(fs.readFileSync(path.join(dir, want), 'utf8'), 'paranoid: true\n');
    });
  }
});
