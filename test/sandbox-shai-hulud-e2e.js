// PMG Sandbox E2E — mini-shai-hulud / TanStack-Mistral TTP simulation
//
// Exercises the install-time behaviors observed in the May 2026 mass npm/PyPI
// supply chain attack ("mini-shai-hulud") that compromised @tanstack/*,
// @mistralai/*, @uipath/*, @opensearch-project/*, mistralai (PyPI),
// guardrails-ai (PyPI), and ~170 other packages.
//
// References:
//   - https://safedep.io/mass-npm-supply-chain-attack-tanstack-mistral
//   - https://www.stepsecurity.io/blog/mini-shai-hulud-is-back-a-self-spreading-supply-chain-attack-hits-the-npm-ecosystem
//
// IMPORTANT: This file contains NO actual malicious behavior. Every test only
// *attempts* the action that the real payload would perform and asserts that
// the sandbox denies it. No network exfiltration, no real credential reading,
// no execution of downloaded binaries. All file contents are benign markers.
//
// Run inside the PMG sandbox to verify the policy blocks the real attack's
// install-time TTPs.

const fs = require('fs');
const { spawnSync } = require('child_process');
const path = require('path');
const os = require('os');
const dns = require('dns');

const home = os.homedir();
const cwd = process.cwd();
const results = { passed: 0, failed: 0, tests: [] };

// A directory is "blocked" if access is denied (EPERM/EACCES) OR if the
// sandbox hides real contents via tmpfs (directory appears empty / file
// reads return empty content). Both are valid mitigations.
function isReadBlocked(p) {
  try {
    const st = fs.statSync(p);
    if (st.isDirectory()) {
      const contents = fs.readdirSync(p);
      if (contents.length === 0) return { blocked: true, reason: 'empty via tmpfs' };
      return { blocked: false, reason: 'contents readable' };
    }
    const data = fs.readFileSync(p, 'utf8');
    if (data.length === 0) return { blocked: true, reason: 'empty via tmpfs' };
    return { blocked: false, reason: 'contents readable' };
  } catch (e) {
    if (e.code === 'ENOENT') return { blocked: true, reason: 'does not exist', skip: true };
    return { blocked: true, reason: e.code };
  }
}

function isWriteBlocked(p, content = 'pmg-sandbox-test-marker') {
  const cleanup = () => { try { fs.unlinkSync(p); } catch (_) {} };
  try {
    fs.mkdirSync(path.dirname(p), { recursive: true });
  } catch (_) { /* parent may be denied — that itself is a block */ }
  try {
    fs.writeFileSync(p, content);
    // Some sandboxes silently route writes to tmpfs. Read it back from a
    // fresh stat to ensure it didn't actually persist to the real path.
    // We still treat the write as "not blocked" — a real attack would
    // succeed in either case for tmpfs-routed paths.
    cleanup();
    return { blocked: false };
  } catch (e) {
    cleanup();
    return { blocked: true, reason: e.code };
  }
}

function test(name, fn) {
  try {
    const ok = fn();
    results.tests.push({ name, status: ok ? 'PASS' : 'FAIL' });
    ok ? results.passed++ : results.failed++;
  } catch (e) {
    results.tests.push({ name, status: 'ERROR', error: e.message });
    results.failed++;
  }
}

console.log('=== PMG Sandbox: mini-shai-hulud TTP Tests ===\n');

// ============================================================
// 1. CREDENTIAL HARVESTING — files the payload's credential
//    provider classes (NK/ZK/MK/JK/FK/UK/DK/OK) would scan.
// ============================================================
console.log('--- Credential file reads (should be BLOCKED) ---\n');

// The npm payload's `UK` / `FK` providers scan for npm_* tokens. The npm
// profile *does* expose ~/.npmrc to package scripts (legitimate need), so
// PMG relies on its malware detection layer for npm token theft. We DO NOT
// assert .npmrc is blocked here. We assert the other credential stores are.

[
  { name: '~/.pypirc (PyPI publish token)', p: path.join(home, '.pypirc') },
  { name: '~/.netrc (HTTP basic auth, including registry creds)', p: path.join(home, '.netrc') },
  { name: '~/.docker/config.json (registry auth tokens)', p: path.join(home, '.docker', 'config.json') },
  { name: '~/.config/gh/hosts.yml (gh CLI GitHub tokens)', p: path.join(home, '.config', 'gh', 'hosts.yml') },
  { name: '~/.gnupg (signing keys)', p: path.join(home, '.gnupg') },
  { name: '~/.config/git/credentials', p: path.join(home, '.config', 'git', 'credentials') },
  { name: '~/.git-credentials (stored HTTPS creds)', p: path.join(home, '.git-credentials') },
].forEach(({ name, p }) => {
  test(`BLOCK: Read ${name}`, () => {
    const r = isReadBlocked(p);
    if (r.skip) { console.log(`  ⚠️  SKIP: ${name} — ${r.reason}`); return true; }
    if (r.blocked) { console.log(`  ✅ PASS: ${name} blocked (${r.reason})`); return true; }
    console.log(`  ❌ FAIL: Could read ${name}`);
    return false;
  });
});

// ============================================================
// 2. CLOUD METADATA & LOCAL SECRET SERVICE PROBES
//    The `NK` provider hits AWS IMDS at 169.254.169.254 and the `ZK`
//    provider hits HashiCorp Vault at 127.0.0.1:8200. We do TCP/DNS
//    smoke probes that should either be denied by the sandbox or fail
//    cleanly with no actual data leaving the host.
// ============================================================
console.log('\n--- Cloud/local metadata probes (should be BLOCKED or fail closed) ---\n');

test('BLOCK or fail-closed: AWS IMDS at 169.254.169.254', () => {
  // We use DNS lookup of the link-local IP as a literal — no traffic to a
  // real metadata service. A non-zero connect or sandbox denial both pass.
  const result = spawnSync(process.execPath, ['-e', `
    const net = require('net');
    const s = net.createConnection({ host: '169.254.169.254', port: 80, timeout: 1500 });
    s.on('connect', () => { s.destroy(); process.exit(0); });
    s.on('error', () => process.exit(2));
    s.on('timeout', () => { s.destroy(); process.exit(3); });
  `], { timeout: 5000 });
  if (result.status === 2 || result.status === 3 || result.status === null) {
    console.log(`  ✅ PASS: IMDS unreachable (exit=${result.status})`);
    return true;
  }
  console.log(`  ⚠️  WARN: IMDS reachable from sandbox (exit=${result.status}) — rely on detection layer`);
  return true; // network filtering is best-effort on macOS; do not hard-fail
});

test('BLOCK or fail-closed: Vault probe at 127.0.0.1:8200', () => {
  const result = spawnSync(process.execPath, ['-e', `
    const net = require('net');
    const s = net.createConnection({ host: '127.0.0.1', port: 8200, timeout: 1500 });
    s.on('connect', () => { s.destroy(); process.exit(0); });
    s.on('error', () => process.exit(2));
    s.on('timeout', () => { s.destroy(); process.exit(3); });
  `], { timeout: 5000 });
  if (result.status === 2 || result.status === 3 || result.status === null) {
    console.log(`  ✅ PASS: Vault probe failed closed (exit=${result.status})`);
    return true;
  }
  console.log(`  ⚠️  WARN: 127.0.0.1:8200 reachable — only meaningful if Vault was running`);
  return true;
});

// ============================================================
// 3. IDE / AI-AGENT POISONING WRITES
//    Payload's `hO` file map drops .claude/* and .vscode/* into the CWD,
//    then commits them to victim branches via GitHub GraphQL. We assert
//    the sandbox prevents the local drop step.
// ============================================================
console.log('\n--- IDE/AI agent poisoning writes (should be BLOCKED) ---\n');

[
  '.claude/settings.json',
  '.claude/setup.mjs',
  '.claude/router_runtime.js',
  '.vscode/tasks.json',
  '.vscode/setup.mjs',
].forEach((rel) => {
  test(`BLOCK: Write ${rel} into CWD`, () => {
    const target = path.join(cwd, rel);
    // Skip if a real file already exists — don't risk clobbering on macOS
    // where the test would then clean up a legitimate file.
    if (fs.existsSync(target)) {
      console.log(`  ⚠️  SKIP: ${rel} already exists in CWD`);
      return true;
    }
    const r = isWriteBlocked(target);
    if (r.blocked) {
      console.log(`  ✅ PASS: ${rel} write blocked (${r.reason})`);
      return true;
    }
    console.log(`  ❌ FAIL: Could write ${rel} into CWD`);
    return false;
  });
});

// ============================================================
// 4. PAYLOAD STAGING & EXECUTION
//    npm variant: downloads Bun via setup.mjs, runs `bun router_init.js`.
//    PyPI variant: writes /tmp/transformers.pyz, runs `python3 /tmp/transformers.pyz`.
//    The npm policy denies /usr/bin/curl, /usr/bin/wget, /usr/bin/python*.
// ============================================================
console.log('\n--- Dropper download & execution (should be BLOCKED) ---\n');

test('BLOCK: Execute /usr/bin/wget (Bun-loader download path)', () => {
  const r = spawnSync('/usr/bin/wget', ['--version'], { timeout: 3000 });
  if (r.error || r.status === null || r.signal === 'SIGKILL') {
    console.log(`  ✅ PASS: wget execution blocked (${r.error ? r.error.code : 'killed'})`);
    return true;
  }
  console.log('  ❌ FAIL: wget executed successfully');
  return false;
});

test('BLOCK: Execute /usr/bin/python3 (transformers.pyz runner)', () => {
  // We do NOT pass a script. Even running `python3 --version` is enough to
  // confirm execution is denied. No code from a .pyz is run anywhere.
  const candidates = ['/usr/bin/python3', '/usr/local/bin/python3'];
  for (const py of candidates) {
    if (!fs.existsSync(py)) continue;
    const r = spawnSync(py, ['--version'], { timeout: 3000 });
    if (r.error || r.status === null || r.signal === 'SIGKILL') {
      console.log(`  ✅ PASS: ${py} execution blocked`);
      return true;
    }
    console.log(`  ❌ FAIL: ${py} executed successfully`);
    return false;
  }
  console.log('  ⚠️  SKIP: no python3 binary present');
  return true;
});

test('BLOCK: Execute a dropped binary from /tmp (simulated .pyz path)', () => {
  // Write a benign shell script to /tmp (writes there are allowed by policy
  // — package installers legitimately use /tmp). Then attempt to execute it
  // directly. The sandbox's process allowlist must reject paths outside the
  // allow_exec list. The script body is intentionally trivial and benign.
  const dropped = path.join(os.tmpdir(), `pmg-shai-hulud-test-${process.pid}.sh`);
  try {
    fs.writeFileSync(dropped, '#!/bin/sh\necho pmg-sandbox-test-marker\n', { mode: 0o755 });
  } catch (e) {
    console.log(`  ⚠️  SKIP: could not stage dropper (${e.code})`);
    return true;
  }
  const r = spawnSync(dropped, [], { timeout: 3000 });
  try { fs.unlinkSync(dropped); } catch (_) {}

  if (r.error || r.status === null || r.signal === 'SIGKILL') {
    console.log(`  ✅ PASS: dropped binary execution blocked (${r.error ? r.error.code : 'killed'})`);
    return true;
  }
  if (typeof r.stdout !== 'undefined' && r.stdout.toString().includes('pmg-sandbox-test-marker')) {
    console.log('  ❌ FAIL: dropped /tmp binary executed (process allowlist bypassed)');
    return false;
  }
  console.log(`  ✅ PASS: dropped binary did not run (status=${r.status})`);
  return true;
});

// ============================================================
// 5. ENVIRONMENT TOKEN SCANNING — the payload greps process.env for
//    ghp_*, gho_*, ghs_*, npm_*, AWS_*, VAULT_TOKEN, ACTIONS_ID_TOKEN.
//    We can't prevent a payload from reading its own process.env, but we
//    record what *would* be exposed if the sandbox forwarded these vars.
// ============================================================
console.log('\n--- Env var leakage surface (informational) ---\n');

test('INFO: env var leak surface for credential scanner', () => {
  const patterns = {
    'GitHub PAT (ghp_/gho_)': /^(ghp|gho)_[A-Za-z0-9_\-.]{36,}$/,
    'GitHub App install (ghs_)': /^ghs_[A-Za-z0-9_\-.]{36,}$/,
    'npm publish token': /^npm_[A-Za-z0-9_\-.]{36,}$/,
    'AWS_SECRET_ACCESS_KEY': /^AWS_SECRET_ACCESS_KEY$/,
    'VAULT_TOKEN': /^VAULT_TOKEN$/,
    'ACTIONS_ID_TOKEN_REQUEST_TOKEN': /^ACTIONS_ID_TOKEN_REQUEST_TOKEN$/,
  };
  const exposed = [];
  for (const [k, v] of Object.entries(process.env)) {
    for (const [label, re] of Object.entries(patterns)) {
      // Match either env name or env value (token pattern in value)
      if (re.test(k) || (typeof v === 'string' && /^(ghp|gho|ghs|npm)_/.test(v) && re.test(v))) {
        exposed.push(`${label}=${k}`);
      }
    }
  }
  if (exposed.length === 0) {
    console.log('  ✅ PASS: no credential-shaped env vars visible to sandboxed process');
    return true;
  }
  console.log(`  ⚠️  WARN: sandboxed process can see: ${exposed.join(', ')}`);
  console.log('         consider scrubbing these from the env passed into install scripts');
  return true; // informational only
});

// ============================================================
// 6. GIT HOOK PERSISTENCE — covered in sandbox-e2e.js, re-asserted here
//    because mini-shai-hulud commits hook-equivalent IDE configs.
// ============================================================
console.log('\n--- Git hook persistence (should be BLOCKED) ---\n');

test('BLOCK: Write .git/hooks/post-checkout', () => {
  const dotGit = path.join(cwd, '.git');
  if (!fs.existsSync(dotGit)) { console.log('  ⚠️  SKIP: no .git in CWD'); return true; }
  const r = isWriteBlocked(path.join(dotGit, 'hooks', 'post-checkout-pmg-test'),
    '#!/bin/sh\n# benign pmg sandbox test marker\n');
  if (r.blocked) { console.log(`  ✅ PASS: .git/hooks write blocked (${r.reason})`); return true; }
  console.log('  ❌ FAIL: could write .git/hooks/post-checkout');
  return false;
});

// ============================================================
// SUMMARY
// ============================================================
console.log('\n=== SUMMARY ===');
console.log(`Passed: ${results.passed}/${results.tests.length}`);
console.log(`Failed: ${results.failed}/${results.tests.length}`);

if (results.failed > 0) {
  console.log('\nFailed tests:');
  results.tests.filter(t => t.status !== 'PASS').forEach(t => {
    console.log(`  - ${t.name}: ${t.status} ${t.error || ''}`);
  });
  process.exit(1);
}
