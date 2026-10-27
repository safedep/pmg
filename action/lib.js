'use strict';

// Helpers that main.js and post.js share. The action has no dependencies, so
// these replace the parts of @actions/core it needs.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const actionDir = __dirname;

function input(name) {
  return (process.env[`INPUT_${name.toUpperCase()}`] || '').trim();
}

function boolInput(name) {
  return input(name).toLowerCase() === 'true';
}

function escapeData(s) {
  return String(s).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
}

function command(kind, message) {
  process.stdout.write(`::${kind}::${escapeData(message)}\n`);
}

const error = (message) => command('error', message);
const warning = (message) => command('warning', message);
const notice = (message) => command('notice', message);

function group(title, fn) {
  process.stdout.write(`::group::${escapeData(title)}\n`);
  try {
    return fn();
  } finally {
    process.stdout.write('::endgroup::\n');
  }
}

function appendFile(name, line) {
  const file = process.env[name];
  if (!file) {
    return;
  }
  fs.appendFileSync(file, `${line}\n`);
}

function saveState(name, value) {
  appendFile('GITHUB_STATE', `${name}=${value}`);
}

function state(name) {
  return process.env[`STATE_${name}`] || '';
}

// fileSize is where a script's appends to a runner file begin.
function fileSize(name) {
  const file = process.env[name];
  try {
    return file ? fs.statSync(file).size : 0;
  } catch (err) {
    if (err.code === 'ENOENT') {
      return 0;
    }
    throw err;
  }
}

function readFrom(name, offset) {
  const file = process.env[name];
  if (!file || !fs.existsSync(file)) {
    return '';
  }
  const fd = fs.openSync(file, 'r');
  try {
    const size = fs.fstatSync(fd).size;
    const buf = Buffer.alloc(Math.max(0, size - offset));
    fs.readSync(fd, buf, 0, buf.length, offset);
    return buf.toString('utf8');
  } finally {
    fs.closeSync(fd);
  }
}

// parseKeyValues reads the NAME=value and NAME<<DELIMITER forms of the
// GITHUB_ENV and GITHUB_OUTPUT files.
function parseKeyValues(text) {
  const out = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].replace(/\r$/, '');
    if (line === '') {
      continue;
    }
    const heredoc = /^([^=<]+)<<(.+)$/.exec(line);
    if (heredoc) {
      const value = [];
      for (i++; i < lines.length && lines[i].replace(/\r$/, '') !== heredoc[2]; i++) {
        value.push(lines[i].replace(/\r$/, ''));
      }
      out.push([heredoc[1], value.join('\n')]);
      continue;
    }
    const eq = line.indexOf('=');
    if (eq > 0) {
      out.push([line.slice(0, eq), line.slice(eq + 1)]);
    }
  }
  return out;
}

// childEnv is the environment of a process that the action starts. The
// runner gives a JavaScript action the tokens of the job, and a run step
// does not get them. The proxy daemon is a long-lived process that every
// step can reach, so it must not keep them.
function childEnv(env = {}) {
  const out = { ...process.env, ...env };
  delete out.ACTIONS_RUNTIME_TOKEN;
  delete out.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  return out;
}

// run starts one setup script. The runner applies GITHUB_ENV and
// GITHUB_PATH only after the step ends, so run applies what the script
// appended to this process, and the next script sees it. It returns the
// outputs and the variables the script wrote. With captureStderr, the log
// shows the stderr of the script after its stdout, and a ScriptError holds
// its last lines.
function run(shell, script, env, { captureStderr = false } = {}) {
  const offsets = {};
  for (const name of ['GITHUB_ENV', 'GITHUB_PATH', 'GITHUB_OUTPUT']) {
    offsets[name] = fileSize(name);
  }
  const res = spawnSync(shell, [path.join(actionDir, script)], {
    stdio: captureStderr ? ['inherit', 'inherit', 'pipe'] : 'inherit',
    encoding: 'utf8',
    env: childEnv({ PMG_ACTION_DIR: actionDir, ...env }),
  });
  if (captureStderr && res.stderr) {
    process.stderr.write(res.stderr);
  }
  if (res.error) {
    throw res.error;
  }
  if (res.status !== 0) {
    throw new ScriptError(script, res.status, lastLines(res.stderr || '', 3), errorCodes(res.stderr || ''));
  }

  const exported = parseKeyValues(readFrom('GITHUB_ENV', offsets.GITHUB_ENV));
  for (const [name, value] of exported) {
    process.env[name] = value;
  }
  for (const dir of readFrom('GITHUB_PATH', offsets.GITHUB_PATH).split('\n')) {
    if (dir.trim() !== '') {
      process.env.PATH = `${dir.trim()}${path.delimiter}${process.env.PATH}`;
    }
  }
  return {
    outputs: Object.fromEntries(parseKeyValues(readFrom('GITHUB_OUTPUT', offsets.GITHUB_OUTPUT))),
    exported,
  };
}

// runPMG runs pmg as the runner user, or as root under enforce, where the
// daemon and its event log belong to root. Only root gets the root
// daemon's config directory. The runner user cannot write it, and every pmg
// command opens the event log there. capture pipes stdout, and 'all'
// pipes stderr too.
function runPMG(bin, args, { sudo = false, configDir = '', capture = false } = {}) {
  let file = bin;
  let argv = args;
  const env = childEnv();
  if (sudo) {
    if (configDir !== '') {
      env.PMG_CONFIG_DIR = configDir;
    }
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

// A ScriptError holds the error codes that pmg printed, so a caller can tell
// a runner that cannot enforce from a policy with an error.
class ScriptError extends Error {
  constructor(script, status, cause = '', codes = []) {
    super(`${script} exited with status ${status}${cause === '' ? '' : `: ${cause}`}`);
    this.status = status;
    this.codes = codes;
  }
}

const stripColors = (text) => text.replace(/\x1b\[[0-9;]*m/g, '');

// errorCodes reads the code that pmg prints first on an error line, as in
// " InvalidArgument   the enforce policy is not valid".
function errorCodes(text) {
  return stripColors(text)
    .split('\n')
    .map((line) => /^\s*([A-Z][A-Za-z]+)\s{2,}\S/.exec(line))
    .filter(Boolean)
    .map((match) => match[1]);
}

function lastLines(text, n) {
  return stripColors(text)
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line !== '' && !line.startsWith('::'))
    .slice(-n)
    .join(' ');
}

// inJobContainer is true when the job runs in a job container. The runner
// mounts its own node at /__e and its work directory at /__w in the
// container. job.container.id is not visible to a JavaScript action.
function inJobContainer() {
  return process.execPath.startsWith('/__e/') || (process.env.RUNNER_TEMP || '').startsWith('/__w/');
}

// isProfilePath matches executor.IsProfilePath in Go: a path, not the name
// of a built-in profile.
function isProfilePath(ref) {
  return /[/\\]/.test(ref) || /\.ya?ml$/i.test(ref);
}

function workspacePath(ref) {
  return path.resolve(process.env.GITHUB_WORKSPACE || process.cwd(), ref);
}

module.exports = {
  actionDir,
  appendFile,
  boolInput,
  childEnv,
  error,
  errorCodes,
  group,
  inJobContainer,
  input,
  isProfilePath,
  lastLines,
  notice,
  parseKeyValues,
  run,
  runPMG,
  saveState,
  ScriptError,
  state,
  warning,
  workspacePath,
};
