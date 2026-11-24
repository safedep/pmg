'use strict';

// The main step of the action: install PMG, export its configuration, and
// either install the shims or start the proxy daemon. post.js stops the
// daemon at the end of the job.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const lib = require('./lib');
const workload = require('./workload');

// runnerErrorCodes are the start failures that come from the runner, not
// from the policy. enforce auto runs the proxy without enforcement only for
// these.
const runnerErrorCodes = ['EnforceRequirements', 'UnsupportedPlatform'];

// policyFetchStatus is the exit status of enforce.sh when no cloud policy
// applies after the fetch. Kernel enforcement did not fail, so the action
// does not say so and does not fall back.
const policyFetchStatus = 3;

const enforceInputs = ['enforce-ports', 'enforce-exempt-users', 'enforce-exempt-executables', 'enforce-skip-destinations', 'enforce-namespaces'];

// rootStatePath is the state file of the root daemon. enforce.sh starts the
// daemon on it, and the failed-start stop reads it.
const rootStatePath = () => path.join(process.env.RUNNER_TEMP || '', 'pmg-proxy-state.json');

function main() {
  if (process.env.RUNNER_OS !== 'Linux') {
    lib.error('safedep/pmg action currently supports Linux runners only. See https://github.com/safedep/pmg/issues/248 for cross-platform tracking.');
    return 1;
  }

  const jobContainer = lib.inJobContainer();
  const profile = lib.input('network-profile');
  const serverMode = resolveServerMode(profile);
  const enforce = choice('enforce', ['auto', 'true', 'false'], 'auto');
  checkInputs(serverMode, enforce);

  const { outputs } = lib.group('Install PMG', () =>
    lib.run('sh', 'install.sh', { INPUT_VERSION: lib.input('version'), INPUT_CACHE: lib.input('cache') }));
  const binDir = outputs['bin-dir'];
  const bin = path.join(binDir, 'pmg');
  exportJobDirs(jobContainer, lib.input('config-file'));
  // Before any script changes the job, so a refused second step leaves the
  // configuration of the first step in place.
  if (serverMode) {
    refuseSecondProxy(bin);
  }

  if (lib.boolInput('sandbox') && !serverMode) {
    lib.group('Prepare the sandbox', () =>
      lib.run('sh', 'sandbox.sh', { INPUT_DRIVER: lib.input('sandbox-driver'), PMG_JOB_CONTAINER: String(jobContainer) }));
  }

  const cloud = cloudInputs(bin, serverMode);
  lib.group('Export PMG configuration', () => lib.run('sh', 'config.sh', {
    INPUT_CONFIG_FILE: lib.input('config-file'),
    IN_API_KEY: cloud.apiKey,
    IN_TENANT_ID: cloud.tenantId,
    IN_ENDPOINT_ID: cloud.endpointId,
    IN_EXPORT_CREDENTIAL: String(cloud.exportCredential),
    IN_CREDENTIAL_FILE: cloud.credentialFile,
    IN_CLOUD_OFF: String(cloud.cloudOff),
    IN_PARANOID: lib.input('paranoid'),
    IN_COOLDOWN_ENABLED: lib.input('cooldown-enabled'),
    IN_COOLDOWN_DAYS: lib.input('cooldown-days'),
    IN_PROXY_MODE: lib.input('proxy-mode'),
    IN_SANDBOX: lib.input('sandbox'),
    IN_SANDBOX_DRIVER: lib.input('sandbox-driver'),
    IN_VERBOSITY: lib.input('verbosity'),
    IN_DISABLE_TELEMETRY: lib.input('disable-telemetry'),
    IN_SKIP_EVENT_LOGGING: lib.input('skip-event-logging'),
    IN_SERVER_MODE: String(serverMode),
    GH_REPOSITORY: process.env.GITHUB_REPOSITORY || '',
  }));

  if (serverMode) {
    startProxy(binDir, profile, enforce, jobContainer, cloud.workload);
  } else {
    lib.group('Install the PMG shims', () => lib.run('sh', 'shim.sh'));
  }

  const verify = spawnSync('sh', ['-c', 'pmg version && printf "%s\\n" "npm resolves to: $(command -v npm || printf "%s" "<not installed>")"'], { stdio: 'inherit', env: lib.helperEnv() });
  return verify.status === 0 ? 0 : 1;
}

// exportJobDirs puts the config and state of PMG under RUNNER_TEMP. Two
// runner agents on one host can run jobs at the same time as one user, and a
// crashed job can leave a proxy or a sync queue. Each runner agent has its
// own RUNNER_TEMP, and the runner empties it after each job. A directory
// that the workflow sets stays, except a config directory when the job sets
// config-file, so the staged file does not change the config of later jobs.
// The cache stays shared, because it holds only regenerable data. A job
// container has its own filesystem, and the proxy CA must stay in
// /github/home there, so Docker actions can read it.
function exportJobDirs(jobContainer, configFile) {
  if (jobContainer) {
    return;
  }
  for (const [name, dir] of [['PMG_CONFIG_DIR', 'config'], ['PMG_STATE_DIR', 'state']]) {
    if (!process.env[name] || (name === 'PMG_CONFIG_DIR' && configFile !== '')) {
      process.env[name] = path.join(process.env.RUNNER_TEMP, 'pmg', dir);
      lib.appendFile('GITHUB_ENV', `${name}=${process.env[name]}`);
    }
    fs.mkdirSync(process.env[name], { recursive: true });
  }
}

// cloudInputs gives the cloud inputs of config.sh. In OIDC mode the access
// token of the workload credential takes the place of the API key. In server
// mode only the proxy gets the credential. The steps of the job do not.
function cloudInputs(bin, serverMode) {
  const none = { apiKey: '', tenantId: '', endpointId: '', exportCredential: true, credentialFile: '', cloudOff: false, workload: null };
  if (workload.cloudMode() !== 'oidc') {
    return { ...none, apiKey: lib.input('api-key'), tenantId: lib.input('tenant-id'), endpointId: lib.input('endpoint-id') };
  }
  const cred = workload.exchange(bin);
  if (cred === null) {
    // The action warned that PMG runs without SafeDep Cloud. A runner
    // config or an earlier step can have turned cloud on, and pmg would
    // then use a saved login of another tenant.
    return { ...none, cloudOff: true };
  }
  return {
    apiKey: cred.AccessToken,
    tenantId: cred.TenantDomain,
    endpointId: cred.EndpointID || '',
    exportCredential: !serverMode,
    credentialFile: serverMode ? '' : cred.file,
    workload: cred,
  };
}

// resolveServerMode is true unless the job asks for shims. The sandbox wraps
// the package managers through the shims, so sandbox true keeps them.
function resolveServerMode(profile) {
  const input = choice('server-mode', ['', 'true', 'false'], '');
  if (profile !== '' && input === 'false') {
    throw new Error('network-profile needs server mode, and server-mode is false. Remove one of them.');
  }
  if (profile !== '' || input === 'true') {
    return true;
  }
  if (input === 'false') {
    return false;
  }
  return !lib.boolInput('sandbox');
}

// choice reads an input that takes one of a few values. A security input
// with a typo must fail, not fall back to a weaker setting.
function choice(name, allowed, fallback) {
  const value = lib.input(name).toLowerCase() || fallback;
  if (!allowed.includes(value)) {
    throw new Error(`${name} must be one of ${allowed.filter((v) => v !== '').join(', ')}, not ${JSON.stringify(lib.input(name))}.`);
  }
  return value;
}

// checkInputs fails on an input that asks for enforcement the action cannot
// give, and warns on an input that has no effect.
function checkInputs(serverMode, enforce) {
  if (enforce === 'true' && !serverMode) {
    throw new Error('enforce true needs server mode. sandbox true and server-mode false select shim mode. Remove one of them.');
  }
  if (lib.boolInput('sandbox') && serverMode) {
    lib.warning('sandbox applies only with shim mode. network-profile or server-mode true turns on server mode, so PMG runs without the sandbox.');
  }
  if (enforce === 'false' && enforceInputsSet()) {
    lib.warning('The enforce-* inputs apply only with kernel enforcement. They are ignored.');
  }
  if (!serverMode && lib.input('network-mode') !== '') {
    lib.warning('network-mode applies only with server mode. It is ignored.');
  }
  if (lib.boolInput('expose-to-job-network') && (!serverMode || enforce === 'true')) {
    lib.warning('expose-to-job-network applies only with server mode and without enforce. It is ignored.');
  }
}

// enforceMode decides whether the daemon starts with kernel enforcement.
// true must enforce or fail. auto enforces on a GitHub-hosted runner, on
// the runner host, with passwordless sudo, and without
// expose-to-job-network. A self-hosted runner can be shared, and
// enforcement adds the PMG CA to its trust store, so it needs true.
function enforceMode(enforce, jobContainer) {
  if (enforce === 'true') {
    return 'required';
  }
  if (enforce === 'false') {
    return 'off';
  }
  const off = 'Set enforce to false to turn off this notice.';
  let reason = '';
  let hint = off;
  if (jobContainer) {
    reason = 'the job runs in a job container';
  } else if (lib.boolInput('expose-to-job-network')) {
    reason = 'expose-to-job-network is set';
  } else if (process.env.RUNNER_ENVIRONMENT !== 'github-hosted') {
    reason = 'the runner is self-hosted';
    hint = 'Set enforce to true to enforce on this runner. ' + off;
  } else if (spawnSync('sudo', ['-n', 'true']).status !== 0) {
    reason = 'the runner has no passwordless sudo';
  }
  if (reason === '') {
    return 'auto';
  }
  // An enforce-* input asks for enforcement. It must not be dropped
  // without a word, as a failed enforced start must not be.
  if (enforceInputsSet()) {
    throw new Error(`The enforce-* inputs need kernel enforcement, and PMG cannot enforce here, because ${reason}. Remove the enforce-* inputs, or set enforce to false.`);
  }
  lib.notice(`PMG runs the proxy without kernel enforcement, because ${reason}. A step can bypass the proxy by dropping the proxy variables. ${hint}`);
  return 'off';
}

function runnerCannotEnforce(err) {
  return err instanceof lib.ScriptError && err.codes.some((code) => runnerErrorCodes.includes(code));
}

// enforcedElsewhere is true when a daemon that this job did not start
// enforces. refuseSecondProxy already refused a daemon of this job.
function enforcedElsewhere(err) {
  return err instanceof lib.ScriptError && err.codes.includes('EnforceAlreadyActive');
}

function failedPolicyFetch(err) {
  return err instanceof lib.ScriptError && err.status === policyFetchStatus;
}

function enforceInputsSet() {
  return enforceInputs.some((name) => lib.input(name) !== '');
}

function startProxy(binDir, profile, enforceInput, jobContainer, cred) {
  const network = networkInputs(profile);
  const env = {
    INPUT_NETWORK_PROFILE: network.profile,
    INPUT_NETWORK_MODE: network.mode,
  };
  // The proxy that runs as the job user gets the credential in its
  // environment. PMG_CLOUD_CREDENTIAL_FILE makes pmg use it before a
  // keychain credential that a self-hosted runner keeps. The root daemon
  // reads a copy that only root can read.
  // config.sh turns cloud off for the later steps of the job, which have no
  // credential. Only the proxy start turns it on.
  const cloudOn = { PMG_CLOUD_ENABLED: 'true', PMG_CLOUD_AUTO_SYNC_ENABLED: 'true' };
  const userEnv = cred
    ? { ...cloudOn, SAFEDEP_API_KEY: cred.AccessToken, SAFEDEP_TENANT_ID: cred.TenantDomain, PMG_CLOUD_CREDENTIAL_FILE: cred.file }
    : {};
  const rootEnv = cred
    ? { ...cloudOn, PMG_WORKLOAD_CREDENTIAL: cred.file, PMG_ROOT_CREDENTIAL_DIR: workload.rootCredentialDir() }
    : {};

  const mode = enforceMode(enforceInput, jobContainer);
  if (mode === 'required' && jobContainer) {
    throw new Error('enforce attaches kernel programs on the runner host, and this job runs in a job container (jobs.<job_id>.container). Run the job on the runner, or set enforce to auto or false.');
  }
  if (mode !== 'off') {
    try {
      startOnce(binDir, true, jobContainer, { ...env, ...rootEnv });
      trustBundleForOldNode();
      return;
    } catch (err) {
      if (failedPolicyFetch(err)) {
        throw err;
      }
      if (enforcedElsewhere(err)) {
        throw new Error('Another PMG daemon on this host already enforces, such as the daemon of a job of another runner agent. PMG enforces for one daemon on each host. Run one runner agent on each host, or set enforce to false.');
      }
      // Only a runner that cannot enforce falls back. A policy error, such
      // as a typo in an enforce-* input or in config-file, fails as
      // choice() does, and does not turn enforcement off.
      const cause = err.message.replace(/\.?$/, '.');
      if (mode === 'required' || enforceInputsSet() || !runnerCannotEnforce(err)) {
        throw new Error(`PMG could not start kernel enforcement: ${cause} Fix the cause, or set enforce to false to run without enforcement.`);
      }
      lib.warning(`PMG could not start kernel enforcement, so it runs the proxy without it: ${cause} Set enforce to true to fail the job instead.`);
      // enforce.sh exports the root daemon's state path before it starts
      // the daemon. A later step and the saved state must not use it.
      for (const name of ['PMG_PROXY_STATE', 'PMG_PROXY_CONFIG_DIR']) {
        lib.appendFile('GITHUB_ENV', `${name}=`);
        delete process.env[name];
      }
    }
  }
  startOnce(binDir, false, jobContainer, { ...env, ...userEnv });
}

function startOnce(binDir, enforce, jobContainer, env) {
  try {
    saveProxyState(binDir, enforce, runStartScript(binDir, enforce, jobContainer, env));
  } catch (err) {
    stopAfterFailedStart(binDir, enforce);
    throw err;
  } finally {
    // enforce.sh makes the root copy of the credential. The post step
    // removes it, also after a failed start.
    if (env.PMG_ROOT_CREDENTIAL_DIR && fs.existsSync(env.PMG_ROOT_CREDENTIAL_DIR)) {
      lib.saveState('root_credential', env.PMG_ROOT_CREDENTIAL_DIR);
    }
  }
}

// trustBundleForOldNode points NODE_EXTRA_CA_CERTS at the system bundle with
// the PMG CA. Under enforcement Node trusts the store only from 22.19 on,
// through NODE_USE_SYSTEM_CA. A value the job sets stays.
function trustBundleForOldNode() {
  const bundle = process.env.PMG_CA_BUNDLE || '';
  if (bundle !== '' && !process.env.NODE_EXTRA_CA_CERTS) {
    lib.appendFile('GITHUB_ENV', `NODE_EXTRA_CA_CERTS=${bundle}`);
  }
}

function runStartScript(binDir, enforce, jobContainer, env) {
  if (enforce) {
    return lib.group('Start the PMG proxy with kernel enforcement', () => lib.run('bash', 'enforce.sh', {
      ...env,
      PMG_BIN_DIR: binDir,
      PMG_ROOT_STATE: rootStatePath(),
      ...Object.fromEntries(enforceInputs.map((name) => [`INPUT_${name.toUpperCase().replace(/-/g, '_')}`, lib.input(name)])),
    }, { captureStderr: true }));
  }
  return lib.group('Start the PMG proxy', () => lib.run('sh', 'server.sh', {
    ...env,
    INPUT_EXPOSE_TO_JOB_NETWORK: String(lib.boolInput('expose-to-job-network')),
    PMG_JOB_CONTAINER: String(jobContainer),
  }));
}

// stopAfterFailedStart stops a daemon after a start script or the state
// save failed. post.js may then lack the state to stop it, and a root
// daemon on a self-hosted runner would outlive the job.
function stopAfterFailedStart(binDir, enforce) {
  const args = ['proxy', 'stop', '--if-running'];
  if (enforce) {
    args.push('--state', rootStatePath());
  }
  let status;
  try {
    status = lib.runPMG(path.join(binDir, 'pmg'), args, { sudo: enforce, configDir: process.env.PMG_PROXY_CONFIG_DIR || '' }).status;
  } catch (err) {
    lib.warning(`PMG could not stop the proxy after the start failed: ${err.message}`);
    return;
  }
  if (status !== 0) {
    lib.warning('PMG could not stop the proxy after the start failed. See the log of the main step.');
  }
}

function saveProxyState(binDir, enforce, result) {
  // post.js reads these. The proxy variables are the ones it clears after
  // the stop, so a later post step, such as a cache save, does not send its
  // traffic to a stopped proxy.
  const proxyVars = result.exported
    .map(([name]) => name)
    .filter(lib.isProxyVar);
  lib.saveState('bin', path.join(binDir, 'pmg'));
  lib.saveState('enforce', String(enforce));
  lib.saveState('state', process.env.PMG_PROXY_STATE || '');
  lib.saveState('config_dir', process.env.PMG_PROXY_CONFIG_DIR || '');
  lib.saveState('run', process.env.PMG_PROXY_RUN || '');
  lib.saveState('proxy_vars', [...new Set(proxyVars)].join(','));
  lib.saveState('pid', daemonPID(path.join(binDir, 'pmg'), enforce, process.env.PMG_PROXY_STATE || ''));
}

// daemonPID lets post.js tell a daemon that a step stopped from one whose
// state file a step removed while it still runs. cmd/proxy/stop_test.go
// pins the status line it reads.
function daemonPID(bin, enforce, statePath) {
  const args = ['proxy', 'status'];
  if (statePath !== '') {
    args.push('--state', statePath);
  }
  const res = lib.runPMG(bin, args, { sudo: enforce, configDir: process.env.PMG_PROXY_CONFIG_DIR || '', capture: 'all' });
  const match = /running \(pid (\d+)/.exec(res.stdout || '');
  return match ? match[1] : '';
}

// refuseSecondProxy fails when an earlier safedep/pmg step of the job left
// a proxy that runs. A second start would fail, and the cleanup after the
// failed start would stop the proxy of the earlier step, on the same state
// path. The later steps would then run without PMG.
function refuseSecondProxy(bin) {
  const paths = [[false, '']];
  if (spawnSync('sudo', ['-n', 'true']).status === 0) {
    paths.push([true, rootStatePath()]);
  }
  for (const [sudo, statePath] of paths) {
    const pid = daemonPID(bin, sudo, statePath);
    if (pid !== '') {
      throw new Error(`A PMG proxy (pid ${pid}) already runs in this job. An earlier safedep/pmg step started it. Use one safedep/pmg step per job.`);
    }
  }
}

// networkInputs passes the network inputs to the daemon. A profile path
// that does not exist yet is a first run in audit mode: the daemon starts
// with no profile, and post.js proposes one for that path.
function networkInputs(profile) {
  const mode = lib.input('network-mode');
  if (profile === '' || !lib.isProfilePath(profile) || fs.existsSync(lib.workspacePath(profile))) {
    return { profile, mode };
  }
  if (mode === 'enforce') {
    throw new Error(`network-profile ${profile} does not exist. Run the job once with network-mode audit. The job summary then proposes the profile to commit.`);
  }
  lib.notice(`network-profile ${profile} does not exist. PMG starts with no network profile and proposes one in the job summary.`);
  return { profile: '', mode: '' };
}

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (err) {
    if (!(err instanceof lib.ScriptError)) {
      lib.error(err.message);
    }
    process.exitCode = 1;
  }
}

module.exports = { checkInputs, enforceMode, enforcedElsewhere, exportJobDirs, failedPolicyFetch, refuseSecondProxy, resolveServerMode, runnerCannotEnforce };
