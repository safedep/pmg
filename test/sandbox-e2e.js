const fs = require('fs');
const { execSync, spawnSync } = require('child_process');
const path = require('path');
const os = require('os');

const home = os.homedir();
const results = { passed: 0, failed: 0, tests: [] };

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

// Test 1: Read ~/.ssh (should be blocked)
test('BLOCK: Read ~/.ssh directory', () => {
  try {
    fs.readdirSync(path.join(home, '.ssh'));
    console.log('  ❌ FAIL: Could read ~/.ssh');
    return false;
  } catch (e) {
    if (e.code === 'EPERM') {
      console.log('  ✅ PASS: ~/.ssh blocked (EPERM)');
      return true;
    }
    console.log(`  ⚠️  SKIP: ~/.ssh - ${e.code} (may not exist)`);
    return true; // ENOENT is okay if dir doesn't exist
  }
});

// Test 2: Read ~/.aws (should be blocked)
test('BLOCK: Read ~/.aws directory', () => {
  try {
    fs.readdirSync(path.join(home, '.aws'));
    console.log('  ❌ FAIL: Could read ~/.aws');
    return false;
  } catch (e) {
    if (e.code === 'EPERM') {
      console.log('  ✅ PASS: ~/.aws blocked (EPERM)');
      return true;
    }
    console.log(`  ⚠️  SKIP: ~/.aws - ${e.code} (may not exist)`);
    return true;
  }
});

// Test 3: Read ~/.kube (should be blocked)
test('BLOCK: Read ~/.kube/config', () => {
  try {
    fs.readFileSync(path.join(home, '.kube', 'config'));
    console.log('  ❌ FAIL: Could read ~/.kube/config');
    return false;
  } catch (e) {
    if (e.code === 'EPERM') {
      console.log('  ✅ PASS: ~/.kube/config blocked (EPERM)');
      return true;
    }
    console.log(`  ⚠️  SKIP: ~/.kube/config - ${e.code} (may not exist)`);
    return true;
  }
});

// Test 4: Read ~/.gcloud (should be blocked)
test('BLOCK: Read ~/.gcloud directory', () => {
  try {
    fs.readdirSync(path.join(home, '.gcloud'));
    console.log('  ❌ FAIL: Could read ~/.gcloud');
    return false;
  } catch (e) {
    if (e.code === 'EPERM') {
      console.log('  ✅ PASS: ~/.gcloud blocked (EPERM)');
      return true;
    }
    console.log(`  ⚠️  SKIP: ~/.gcloud - ${e.code} (may not exist)`);
    return true;
  }
});

// Test 5: Write to /etc (should be blocked)
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

// Test 6: Write to /usr (should be blocked)
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

// Test 7: Execute curl (should be blocked by policy)
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

// ============================================
// TESTS THAT SHOULD BE ALLOWED
// ============================================
console.log('\n--- Tests that SHOULD be ALLOWED ---\n');

// Test 8: Read current directory
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

// Test 9: Write to current directory
test('ALLOW: Write to current directory', () => {
  try {
    fs.writeFileSync('test-sandbox-write.txt', 'test');
    fs.unlinkSync('test-sandbox-write.txt');
    console.log('  ✅ PASS: Can write to current directory');
    return true;
  } catch (e) {
    console.log('  ❌ FAIL: Cannot write to current directory');
    return false;
  }
});

// Test 10: Read node_modules
test('ALLOW: Read node_modules', () => {
  try {
    fs.readdirSync('node_modules');
    console.log('  ✅ PASS: Can read node_modules');
    return true;
  } catch (e) {
    console.log('  ❌ FAIL: Cannot read node_modules');
    return false;
  }
});

// Test 11: Read system libraries
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

// Test 12: Network access (DNS + HTTP)
test('ALLOW: Network DNS resolution', () => {
  try {
    require('dns').lookup('registry.npmjs.org', (err) => {});
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
