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
  const pmg = (args, opts = {}) => lib.runPMG(bin, args, { sudo: enforce, configDir: lib.state('config_dir'), ...opts });

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
    const message = 'PMG could not stop the proxy, so the job has no verdict. The daemon may have exited before the post step. See the log of the post step, and re-run the job.';
    lib.error(message);
    lib.appendFile('GITHUB_STEP_SUMMARY', `## PMG\n\n**Failed.** ${message}\n`);
    return stop.status || 1;
  }

  const report = JSON.parse(fs.readFileSync(reportPath, 'utf8'));
  let status = stop.status ?? 1;
  let lost = false;
  if (!report.stopped) {
    const check = checkNotRunning(failOnViolation);
    lost = check.lost;
    status = Math.max(status, check.status);
  }
  // A proposal reads the run from the event log.
  const baseline = lib.boolInput('baseline') && !lib.boolInput('skip-event-logging');
  let proposalPath = '';
  if (baseline && !lost && (!report.stopped || report.observed > 0)) {
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
  if (lib.runPMG(bin, summaryArgs).status !== 0) {
    lib.warning('PMG could not write the job summary. See the log of the post step.');
  }
  return status;
}

// checkNotRunning handles a post step that finds no proxy state. The
// denials and blocks of the run die with the state, so a step that stops
// PMG can hide them. With fail-on-violation the job fails. lost is true
// when a step removed the state file of a daemon that still runs.
function checkNotRunning(failOnViolation) {
  const pid = lib.state('pid');
  if (pid !== '' && pmgRuns(pid)) {
    lib.error(`The PMG proxy (pid ${pid}) still runs, but its state file is gone. A step of the job removed it, so the job has no verdict.`);
    return { status: 1, lost: true };
  }
  const message = 'The PMG proxy was not running at the end of the job, so the job has no verdict. When a step of the job stops PMG, set auto-stop to false.';
  if (failOnViolation) {
    lib.error(message);
    return { status: 1, lost: false };
  }
  lib.warning(message);
  return { status: 0, lost: false };
}

// pmgRuns is true when pid is a live pmg process. A stopped daemon that no
// init process reaps stays as a zombie, and a new process can reuse the pid.
function pmgRuns(pid) {
  let stat;
  try {
    stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      return false;
    }
    throw err;
  }
  const open = stat.indexOf('(');
  const close = stat.lastIndexOf(')');
  const comm = stat.slice(open + 1, close);
  const processState = stat.slice(close + 2, close + 3);
  return comm === 'pmg' && processState !== 'Z';
}

function stateArgs(enforce) {
  return enforce ? ['--state', lib.state('state')] : [];
}

// supportsReport is false for a PMG release older than the job summary.
// The action installs the release that the version input names.
function supportsReport(bin) {
  const res = spawnSync(bin, ['proxy', 'stop', '--help'], { encoding: 'utf8' });
  return res.status === 0 && res.stdout.includes('--if-running');
}

function legacyStop(pmg, enforce, failOnViolation) {
  lib.notice('This PMG release has no job summary. Set the version input to v0.34.0 or later to get one.');
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
  if (!lib.isProfilePath(profile)) {
    args.push('--new', path.join(tmp, 'proposal', 'network.yml'), '--dry-run');
  } else {
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

if (require.main === module) {
  try {
    process.exitCode = main();
  } catch (err) {
    lib.error(err.message);
    process.exitCode = 1;
  }
}

module.exports = { checkNotRunning, pmgRuns };
