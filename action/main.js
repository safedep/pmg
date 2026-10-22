'use strict';

// The main step of the action: install PMG, export its configuration, and
// either install the shims or start the proxy daemon. post.js stops the
// daemon at the end of the job.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const lib = require('./lib');

const enforceInputs = ['enforce-ports', 'enforce-exempt-users', 'enforce-exempt-executables', 'enforce-skip-destinations', 'enforce-namespaces'];

function main() {
  if (process.env.RUNNER_OS !== 'Linux') {
    lib.error('safedep/pmg action currently supports Linux runners only. See https://github.com/safedep/pmg/issues/248 for cross-platform tracking.');
    return 1;
  }

  const jobContainer = lib.inJobContainer();
  const enforce = lib.boolInput('enforce');
  const profile = lib.input('network-profile');
  const serverMode = lib.boolInput('server-mode') || profile !== '';
  warnIgnoredInputs(serverMode, enforce);

  const { outputs } = lib.group('Install PMG', () =>
    lib.run('sh', 'install.sh', { INPUT_VERSION: lib.input('version'), INPUT_CACHE: lib.input('cache') }));
  const binDir = outputs['bin-dir'];

  if (lib.boolInput('sandbox')) {
    lib.group('Prepare the sandbox', () =>
      lib.run('sh', 'sandbox.sh', { INPUT_DRIVER: lib.input('sandbox-driver'), PMG_JOB_CONTAINER: String(jobContainer) }));
  }

  lib.group('Export PMG configuration', () => lib.run('sh', 'config.sh', {
    INPUT_CONFIG_FILE: lib.input('config-file'),
    IN_API_KEY: lib.input('api-key'),
    IN_TENANT_ID: lib.input('tenant-id'),
    IN_ENDPOINT_ID: lib.input('endpoint-id'),
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
    startProxy(binDir, profile, enforce, jobContainer);
  } else {
    lib.group('Install the PMG shims', () => lib.run('sh', 'shim.sh'));
  }

  const verify = spawnSync('sh', ['-c', 'pmg version && printf "%s\\n" "npm resolves to: $(command -v npm || printf "%s" "<not installed>")"'], { stdio: 'inherit' });
  return verify.status === 0 ? 0 : 1;
}

function warnIgnoredInputs(serverMode, enforce) {
  if (!enforce && enforceInputs.some((name) => lib.input(name) !== '')) {
    lib.warning('The enforce-* inputs apply only with enforce true. They are ignored.');
  }
  if (!serverMode && lib.input('network-mode') !== '') {
    lib.warning('network-mode applies only with network-profile or server-mode true. It is ignored.');
  }
  if (enforce && !serverMode) {
    lib.warning('enforce applies only with server-mode true or network-profile. It is ignored.');
  }
  if (lib.boolInput('expose-to-job-network') && (!serverMode || enforce)) {
    lib.warning('expose-to-job-network applies only with server-mode true and enforce false. It is ignored.');
  }
}

function startProxy(binDir, profile, enforce, jobContainer) {
  const network = networkInputs(profile);
  const env = {
    INPUT_NETWORK_PROFILE: network.profile,
    INPUT_NETWORK_MODE: network.mode,
  };

  let result;
  if (enforce) {
    if (jobContainer) {
      throw new Error('enforce attaches kernel programs on the runner host, and this job runs in a job container (jobs.<job_id>.container). Run the job on the runner, or use server-mode without enforce.');
    }
    result = lib.group('Start the PMG proxy with kernel enforcement', () => lib.run('bash', 'enforce.sh', {
      ...env,
      PMG_BIN_DIR: binDir,
      INPUT_CONFIG_FILE: lib.input('config-file'),
      INPUT_ENFORCE_PORTS: lib.input('enforce-ports'),
      INPUT_ENFORCE_EXEMPT_USERS: lib.input('enforce-exempt-users'),
      INPUT_ENFORCE_EXEMPT_EXECUTABLES: lib.input('enforce-exempt-executables'),
      INPUT_ENFORCE_SKIP_DESTINATIONS: lib.input('enforce-skip-destinations'),
      INPUT_ENFORCE_NAMESPACES: lib.input('enforce-namespaces'),
    }));
  } else {
    result = lib.group('Start the PMG proxy', () => lib.run('sh', 'server.sh', {
      ...env,
      INPUT_EXPOSE_TO_JOB_NETWORK: String(lib.boolInput('expose-to-job-network')),
      PMG_JOB_CONTAINER: String(jobContainer),
    }));
  }

  // post.js reads these. The proxy variables are the ones it clears after
  // the stop, so a later post step, such as a cache save, does not send its
  // traffic to a stopped proxy.
  const proxyVars = result.exported
    .map(([name]) => name)
    .filter((name) => /proxy/i.test(name) && !name.startsWith('PMG_PROXY_'));
  lib.saveState('bin', path.join(binDir, 'pmg'));
  lib.saveState('enforce', String(enforce));
  lib.saveState('state', process.env.PMG_PROXY_STATE || '');
  lib.saveState('config_dir', process.env.PMG_PROXY_CONFIG_DIR || '');
  lib.saveState('run', process.env.PMG_PROXY_RUN || '');
  lib.saveState('proxy_vars', [...new Set(proxyVars)].join(','));
  lib.saveState('pid', daemonPID(path.join(binDir, 'pmg'), enforce));
}

// daemonPID lets post.js tell a daemon that a step stopped from one whose
// state file a step removed while it still runs.
function daemonPID(bin, enforce) {
  const args = ['proxy', 'status'];
  if (enforce) {
    args.push('--state', process.env.PMG_PROXY_STATE || '');
  }
  const res = enforce
    ? spawnSync('sudo', ['-n', bin, ...args], { encoding: 'utf8' })
    : spawnSync(bin, args, { encoding: 'utf8' });
  const match = /running \(pid (\d+)/.exec(res.stdout || '');
  return match ? match[1] : '';
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

try {
  process.exitCode = main();
} catch (err) {
  if (!(err instanceof lib.ScriptError)) {
    lib.error(err.message);
  }
  process.exitCode = 1;
}
