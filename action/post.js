'use strict';

// The post step of the action. At the end of the job it stops the proxy
// daemon that main.js started, proposes a network profile from the run, and
// writes the job summary. Its exit status is the stop verdict.

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const lib = require('./lib');

function main() {
  const bin = lib.state('bin');
  if (bin === '') {
    return 0;
  }
  if (!lib.boolInput('auto-stop')) {
    console.log('auto-stop is off. A workflow step must stop the PMG proxy.');
    return 0;
  }

  const enforce = lib.state('enforce') === 'true';
  const failOnViolation = lib.boolInput('fail-on-violation');
  const profile = lib.input('network-profile');
  const tmp = fs.mkdtempSync(path.join(process.env.RUNNER_TEMP || os.tmpdir(), 'pmg-post-'));
  const pmg = (args, opts = {}) => runPMG(bin, args, { sudo: enforce, ...opts });

  if (!supportsReport(bin)) {
    return legacyStop(pmg, enforce, failOnViolation);
  }

  const reportPath = path.join(tmp, 'stop.json');
  const stopArgs = ['proxy', 'stop', '--if-running', '--report', reportPath, ...stateArgs(enforce)];
  if (failOnViolation) {
    stopArgs.push('--fail-on-violation');
  }
  const stop = lib.group('Stop the PMG proxy', () => pmg(stopArgs));
  clearProxyVars();

  if (!fs.existsSync(reportPath)) {
    lib.error('PMG could not stop the proxy, so the job has no verdict. See the log of the post step.');
    return stop.status || 1;
  }

  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  let proposalPath = '';
  if (lib.boolInput('baseline') && (!report.stopped || report.observed > 0)) {
    proposalPath = lib.group('Propose a network profile', () =>
      propose(pmg, report.run_id || lib.state('run'), profile, tmp));
  }

  const summaryArgs = ['proxy', 'github-summary', '--report', reportPath];
  if (proposalPath !== '') {
    summaryArgs.push('--proposal', proposalPath);
  }
  if (profile !== '') {
    summaryArgs.push('--profile', profile);
  }
  if (failOnViolation) {
    summaryArgs.push('--fail-on-violation');
  }
  if (runPMG(bin, summaryArgs).status !== 0) {
    lib.warning('PMG could not write the job summary. See the log of the post step.');
  }
  return stop.status ?? 1;
}

function stateArgs(enforce) {
  return enforce ? ['--state', lib.state('state')] : [];
}

// runPMG runs pmg as the runner user, or as root under enforce, where the
// daemon and its event log belong to root. The runtime token of the job is
// not passed to root.
function runPMG(bin, args, { sudo = false, capture = false } = {}) {
  let file = bin;
  let argv = args;
  const env = { ...process.env };
  delete env.ACTIONS_RUNTIME_TOKEN;
  if (lib.state('config_dir') !== '') {
    env.PMG_CONFIG_DIR = lib.state('config_dir');
  }
  if (sudo) {
    file = 'sudo';
    argv = ['-n', '--preserve-env=PMG_CONFIG_DIR,GITHUB_ACTIONS', bin, ...args];
  }
  const res = spawnSync(file, argv, {
    env,
    stdio: capture ? ['ignore', 'pipe', capture === 'all' ? 'pipe' : 'inherit'] : 'inherit',
    encoding: 'utf8',
  });
  if (res.error) {
    throw res.error;
  }
  return res;
}

// supportsReport is false for a PMG release older than the job summary.
// The action installs the release that the version input names.
function supportsReport(bin) {
  const res = spawnSync(bin, ['proxy', 'stop', '--help'], { encoding: 'utf8' });
  return res.status === 0 && res.stdout.includes('--if-running');
}

function legacyStop(pmg, enforce, failOnViolation) {
  lib.notice('This PMG release has no job summary. Use a newer release in the version input to get one.');
  const args = ['proxy', 'stop', ...stateArgs(enforce)];
  if (failOnViolation) {
    args.push('--fail-on-violation');
  }
  const stop = lib.group('Stop the PMG proxy', () => {
    const res = pmg(args, { capture: 'all' });
    process.stdout.write(res.stdout + res.stderr);
    return res;
  });
  clearProxyVars();
  if (stop.status !== 0 && /no proxy state found|File or directory not found/.test(stop.stdout + stop.stderr)) {
    return 0;
  }
  return stop.status ?? 1;
}

// clearProxyVars empties the proxy variables for the post steps that run
// after this one. The steps before the action, such as actions/setup-node
// with a cache, run their post steps later and would otherwise send their
// traffic to the stopped proxy. The CA variables stay, because they are
// harmless without a proxy.
function clearProxyVars() {
  for (const name of lib.state('proxy_vars').split(',')) {
    if (name !== '') {
      lib.appendFile('GITHUB_ENV', `${name}=`);
    }
  }
}

// propose returns the path of the proposal JSON, or empty when PMG cannot
// make one. A missing proposal is a warning, never a job failure.
function propose(pmg, runId, profile, tmp) {
  if (!runId) {
    lib.warning('The proxy reported no run id, so PMG cannot propose a network profile.');
    return '';
  }
  const args = ['sandbox', 'profile', 'propose', '--run', runId, '--json'];
  if (profile === '') {
    args.push('--new', path.join(tmp, 'proposal', 'network.yml'), '--dry-run');
  } else if (lib.isProfilePath(profile)) {
    const file = lib.workspacePath(profile);
    args.push(fs.existsSync(file) ? '--into' : '--new', file, '--dry-run');
  }
  const res = pmg(args, { capture: true });
  if (res.status !== 0) {
    lib.warning('PMG could not propose a network profile. See the log of the post step.');
    return '';
  }
  const out = path.join(tmp, 'proposal.json');
  fs.writeFileSync(out, res.stdout);
  return out;
}

try {
  process.exitCode = main();
} catch (err) {
  lib.error(err.message);
  process.exitCode = 1;
}
