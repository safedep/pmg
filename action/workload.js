'use strict';

// tenant-id with no api-key selects OIDC mode. The main step exchanges the GitHub
// Actions ID token for a SafeDep Cloud credential before it starts the
// proxy. The proxy cannot refresh the credential and never gets the ID token
// request token. The post step revokes the credential.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const lib = require('./lib');

const noTokenCode = 'WorkloadIdentityNotFound';
const refusedCode = 'WorkloadExchangeRefused';

// rootCredentialDir holds the copy of the credential that the root daemon
// reads. enforce.sh makes it, and only root can read it.
const rootCredentialDir = () => path.join(process.env.RUNNER_TEMP || '', 'pmg-daemon-credential');

// cloudMode is api-key when the job sets api-key, so that both inputs work
// during a migration. tenant-id alone selects OIDC.
function cloudMode() {
  if (lib.input('api-key') !== '') {
    return 'api-key';
  }
  return lib.input('tenant-id') !== '' ? 'oidc' : '';
}

// isForkPullRequest is true for a pull_request run from a fork. GitHub gives
// such a run no ID token. A head repository that is gone is a fork too.
function isForkPullRequest() {
  if (process.env.GITHUB_EVENT_NAME !== 'pull_request' || !process.env.GITHUB_EVENT_PATH) {
    return false;
  }
  const event = JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, 'utf8'));
  const pr = event.pull_request || {};
  const head = pr.head && pr.head.repo;
  const base = pr.base && pr.base.repo;
  return !head || !base || head.full_name !== base.full_name;
}

function hasIDToken() {
  return Boolean(process.env.ACTIONS_ID_TOKEN_REQUEST_URL && process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN);
}

function supportsWorkload(bin) {
  const res = spawnSync(bin, ['cloud', 'workload', 'exchange', '--help'], { encoding: 'utf8', env: lib.helperEnv() });
  return res.status === 0 && res.stdout.includes('--tenant-id');
}

// exchange returns the workload credential. It returns null on a
// pull_request from a fork with no ID token, and when SafeDep Cloud refuses
// the exchange. PMG then runs without SafeDep Cloud. Any other error fails
// the step.
function exchange(bin) {
  const tenant = lib.input('tenant-id');
  if (lib.input('endpoint-id') !== '') {
    lib.warning('In OIDC mode SafeDep Cloud sets the endpoint id from the claims of the ID token. The endpoint-id input is ignored.');
  }
  if (!hasIDToken() && isForkPullRequest()) {
    lib.warning('This pull_request run comes from a fork, and GitHub gives it no ID token. PMG runs without SafeDep Cloud.');
    return null;
  }
  // The proxy start replaces the proxy variables of the job. The revoke in
  // the post step needs the proxy of the runner, such as the upstream proxy
  // of a self-hosted runner, and not the stopped proxy of the action.
  lib.saveState('runner_proxy', JSON.stringify(Object.fromEntries(Object.entries(process.env).filter(([name]) => lib.isProxyVar(name)))));
  if (!supportsWorkload(bin)) {
    throw new Error('OIDC mode needs a PMG release with "pmg cloud workload exchange". Set the version input to such a release, or set the api-key input.');
  }

  const dir = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'pmg-workload-'));
  const file = path.join(dir, 'credential.json');
  const res = lib.group('Exchange the GitHub ID token for a SafeDep Cloud credential', () => {
    const out = lib.runPMG(bin, ['cloud', 'workload', 'exchange', '--tenant-id', tenant, '--output', file], { capture: 'all', idToken: true });
    process.stdout.write(out.stdout + out.stderr);
    return out;
  });

  if (res.status === 0) {
    const cred = JSON.parse(fs.readFileSync(file, 'utf8'));
    lib.saveState('credential', file);
    lib.saveState('credential_bin', bin);
    return { file, ...cred };
  }
  fs.rmSync(dir, { recursive: true, force: true });

  const codes = lib.errorCodes(res.stderr || '');
  if (codes.includes(noTokenCode)) {
    throw new Error('PMG cannot get a SafeDep Cloud credential, because the job has no ID token. Give the job "permissions: id-token: write", or set the api-key input.');
  }
  if (codes.includes(refusedCode)) {
    const reason = lib.lastLines(res.stderr || '', 3);
    lib.warning(`SafeDep Cloud refused the workload identity exchange for ${tenant}. PMG runs with its local config.`);
    lib.appendFile('GITHUB_STEP_SUMMARY', `## PMG\n\nSafeDep Cloud refused the workload identity exchange for \`${tenant}\`. PMG runs with its local config, without SafeDep Cloud.\n\n\`\`\`text\n${reason}\n\`\`\`\n`);
    return null;
  }
  throw new Error(`PMG could not exchange the GitHub ID token for a SafeDep Cloud credential: ${lib.lastLines(res.stderr || '', 3)}`);
}

// end runs in the post step on every job outcome, after the proxy stop. A
// proxy that outlives the job on a persistent runner would serve later jobs
// under this credential, so the post step fails when the proxy still runs.
// It revokes the credential in every case.
function end(pmgRuns) {
  const file = lib.state('credential');
  if (file === '') {
    return 0;
  }
  let status = 0;
  const pid = lib.state('pid');
  if (pid !== '' && pmgRuns(pid)) {
    lib.error(`The PMG proxy (pid ${pid}) still runs at the end of the job. It could serve later jobs on this runner. Stop the proxy in a step, or set auto-stop to true.`);
    status = 1;
  }

  try {
    // The post step keeps the proxy variables of the main step, and the
    // proxy is stopped. The revoke uses the proxy variables that the runner
    // had before the action changed them.
    const res = lib.group('Revoke the SafeDep Cloud credential', () =>
      lib.runPMG(lib.state('credential_bin'), ['cloud', 'workload', 'revoke', '--credential', file], { proxyEnv: runnerProxy() }));
    if (res.status !== 0) {
      lib.warning('PMG could not revoke the SafeDep Cloud credential. It stays valid until it expires. See the log of the post step.');
    }
  } finally {
    removeCopies(file);
  }
  return status;
}

function runnerProxy() {
  const saved = lib.state('runner_proxy');
  return saved === '' ? {} : JSON.parse(saved);
}

function removeCopies(file) {
  fs.rmSync(path.dirname(file), { recursive: true, force: true });
  const root = lib.state('root_credential');
  if (root === '') {
    return;
  }
  const rm = spawnSync('sudo', ['-n', 'rm', '-rf', root], { stdio: 'inherit' });
  if (rm.status !== 0) {
    lib.warning(`PMG could not remove ${root}.`);
  }
}

module.exports = { cloudMode, end, exchange, isForkPullRequest, rootCredentialDir };
