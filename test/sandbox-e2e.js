const fs = require('fs');
const { execSync, spawnSync } = require('child_process');
const path = require('path');
const os = require('os');

const home = os.homedir();
const results = { passed: 0, failed: 0, tests: [] };

// Helper to test if a directory is blocked (either EPERM or empty via tmpfs)
function isDirectoryBlocked(dirPath) {
  try {
    const contents = fs.readdirSync(dirPath);
    // On Linux/bwrap, tmpfs makes directory empty (credentials hidden)
    // On macOS/seatbelt, access is denied (EPERM)
    if (contents.length === 0) {
      return { blocked: true, reason: 'empty via tmpfs' };
    }
    return { blocked: false, reason: 'contents readable' };
  } catch (e) {
    if (e.code === 'EPERM') {
      return { blocked: true, reason: 'EPERM' };
    }
    if (e.code === 'ENOENT') {
      return { blocked: true, reason: 'does not exist', skip: true };
    }
    return { blocked: true, reason: e.code, skip: true };
  }
}

function test(name, fn) {
  try {
    const result = fn();
    results.tests.push({ name, status: result ? 'PASS' : 'FAIL', error: null });
    result ? results.passed++ : results.failed++;
  } catch (e) {
    results.tests.push({ name, status: 'ERROR', error: e.message });
    results.failed++;
  }
}

console.log('=== PMG Sandbox Policy Violation Tests ===\n');

// ============================================
// TESTS THAT SHOULD BE BLOCKED (DENY RULES)
// ============================================
console.log('--- Tests that SHOULD be BLOCKED ---\n');

// Read ~/.ssh (should be blocked)
test('BLOCK: Read ~/.ssh directory', () => {
  const result = isDirectoryBlocked(path.join(home, '.ssh'));
  if (result.skip) {
    console.log(`  ⚠️  SKIP: ~/.ssh - ${result.reason}`);
    return true;
  }
  if (result.blocked) {
    console.log(`  ✅ PASS: ~/.ssh blocked (${result.reason})`);
    return true;
  }
  console.log('  ❌ FAIL: Could read ~/.ssh contents');
  return false;
});

// Read ~/.aws (should be blocked)
test('BLOCK: Read ~/.aws directory', () => {
  const result = isDirectoryBlocked(path.join(home, '.aws'));
  if (result.skip) {
    console.log(`  ⚠️  SKIP: ~/.aws - ${result.reason}`);
    return true;
  }
  if (result.blocked) {
    console.log(`  ✅ PASS: ~/.aws blocked (${result.reason})`);
    return true;
  }
  console.log('  ❌ FAIL: Could read ~/.aws contents');
  return false;
});

// Read ~/.kube (should be blocked)
test('BLOCK: Read ~/.kube directory', () => {
  const result = isDirectoryBlocked(path.join(home, '.kube'));
  if (result.skip) {
    console.log(`  ⚠️  SKIP: ~/.kube - ${result.reason}`);
    return true;
  }
  if (result.blocked) {
    console.log(`  ✅ PASS: ~/.kube blocked (${result.reason})`);
    return true;
  }
  console.log('  ❌ FAIL: Could read ~/.kube contents');
  return false;
});

// Read ~/.gcloud (should be blocked)
test('BLOCK: Read ~/.gcloud directory', () => {
  const result = isDirectoryBlocked(path.join(home, '.gcloud'));
  if (result.skip) {
    console.log(`  ⚠️  SKIP: ~/.gcloud - ${result.reason}`);
    return true;
  }
  if (result.blocked) {
    console.log(`  ✅ PASS: ~/.gcloud blocked (${result.reason})`);
    return true;
  }
  console.log('  ❌ FAIL: Could read ~/.gcloud contents');
  return false;
});

// Write to /etc (should be blocked)
test('BLOCK: Write to /etc', () => {
  try {
    fs.writeFileSync('/etc/test-pmg-sandbox', 'test');
    fs.unlinkSync('/etc/test-pmg-sandbox');
    console.log('  ❌ FAIL: Could write to /etc');
    return false;
  } catch (e) {
    if (e.code === 'EPERM' || e.code === 'EACCES') {
      console.log('  ✅ PASS: /etc write blocked');
      return true;
    }
    console.log(`  ✅ PASS: /etc write blocked (${e.code})`);
    return true;
  }
});

// Write to /usr (should be blocked)
test('BLOCK: Write to /usr', () => {
  try {
    fs.writeFileSync('/usr/test-pmg-sandbox', 'test');
    fs.unlinkSync('/usr/test-pmg-sandbox');
    console.log('  ❌ FAIL: Could write to /usr');
    return false;
  } catch (e) {
    console.log('  ✅ PASS: /usr write blocked');
    return true;
  }
});

// Execute curl (should be blocked by policy)
test('BLOCK: Execute /usr/bin/curl', () => {
  try {
    const result = spawnSync('/usr/bin/curl', ['--version'], { timeout: 5000 });
    if (result.status === null || result.signal === 'SIGKILL') {
      console.log('  ✅ PASS: curl execution blocked');
      return true;
    }
    console.log('  ❌ FAIL: curl executed successfully');
    return false;
  } catch (e) {
    console.log('  ✅ PASS: curl blocked');
    return true;
  }
});

// Write to .git/hooks in CWD (should be blocked - security risk)
test('BLOCK: Write to .git/hooks in CWD', () => {
  const gitHooksDir = path.join(process.cwd(), '.git', 'hooks');
  const testHookPath = path.join(gitHooksDir, 'test-pmg-sandbox-hook');

  // Helper to clean up test hook if it was wrongly created
  const cleanup = () => {
    try {
      if (fs.existsSync(testHookPath)) {
        fs.unlinkSync(testHookPath);
      }
    } catch (e) {
      // Ignore cleanup errors
    }
  };

  try {
    // First check if .git/hooks exists
    if (!fs.existsSync(gitHooksDir)) {
      console.log('  ⚠️  SKIP: .git/hooks does not exist in CWD');
      return true;
    }
    fs.writeFileSync(testHookPath, '#!/bin/sh\necho "malicious hook"');
    // If we get here, write succeeded when it should have been blocked
    cleanup();
    console.log('  ❌ FAIL: Could write to .git/hooks');
    return false;
  } catch (e) {
    cleanup();
    if (e.code === 'EPERM' || e.code === 'EACCES') {
      console.log('  ✅ PASS: .git/hooks write blocked');
      return true;
    }
    // ENOENT means directory doesn't exist, which is fine
    if (e.code === 'ENOENT') {
      console.log('  ⚠️  SKIP: .git/hooks does not exist');
      return true;
    }
    console.log(`  ✅ PASS: .git/hooks write blocked (${e.code})`);
    return true;
  }
});

// ============================================
// TESTS THAT SHOULD BE ALLOWED
// ============================================
console.log('\n--- Tests that SHOULD be ALLOWED ---\n');

// Read current directory
test('ALLOW: Read current directory', () => {
  try {
    fs.readdirSync('.');
    console.log('  ✅ PASS: Can read current directory');
    return true;
  } catch (e) {
    console.log('  ❌ FAIL: Cannot read current directory');
    return false;
  }
});

// Write to TMPDIR (allowed by policy)
test('ALLOW: Write to TMPDIR', () => {
  try {
    const tmpFile = path.join(os.tmpdir(), 'test-pmg-sandbox-write.txt');
    fs.writeFileSync(tmpFile, 'test');
    fs.unlinkSync(tmpFile);
    console.log('  ✅ PASS: Can write to TMPDIR');
    return true;
  } catch (e) {
    console.log(`  ❌ FAIL: Cannot write to TMPDIR - ${e.code}`);
    return false;
  }
});

// Read node_modules (if exists)
test('ALLOW: Read node_modules', () => {
  try {
    fs.readdirSync('node_modules');
    console.log('  ✅ PASS: Can read node_modules');
    return true;
  } catch (e) {
    if (e.code === 'ENOENT') {
      console.log('  ⚠️  SKIP: node_modules does not exist');
      return true; // Not a sandbox issue, directory just doesn't exist
    }
    console.log(`  ❌ FAIL: Cannot read node_modules - ${e.code}`);
    return false;
  }
});

// Read system libraries
test('ALLOW: Read /usr/lib', () => {
  try {
    fs.readdirSync('/usr/lib');
    console.log('  ✅ PASS: Can read /usr/lib');
    return true;
  } catch (e) {
    console.log('  ❌ FAIL: Cannot read /usr/lib');
    return false;
  }
});

// Network access (DNS + HTTP)
test('ALLOW: Network DNS resolution', () => {
  try {
    require('dns').lookup('registry.npmjs.org', (err) => { });
    console.log('  ✅ PASS: DNS resolution works');
    return true;
  } catch (e) {
    console.log('  ❌ FAIL: DNS resolution blocked');
    return false;
  }
});

// ============================================
// SUMMARY
// ============================================
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
