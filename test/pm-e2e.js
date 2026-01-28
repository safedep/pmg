const fs = require('fs');
const { execSync } = require('child_process');
const path = require('path');
const os = require('os');

// Package managers to test
const PACKAGE_MANAGERS = ['npm', 'pnpm'];

// Well-known dependencies to install
const TEST_DEPENDENCIES = ['lodash'];

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

function exec(cmd, options = {}) {
  try {
    const output = execSync(cmd, {
      encoding: 'utf8',
      timeout: 120000, // 2 minutes
      ...options
    });
    return { success: true, output };
  } catch (e) {
    return { success: false, error: e.message, output: e.stdout || '' };
  }
}

function createTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function cleanup(dir) {
  try {
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    // Ignore cleanup errors
  }
}

function testPackageManager(pm) {
  const testDir = createTempDir(`pmg-e2e-${pm}-`);
  console.log(`\n  Test directory: ${testDir}`);

  try {
    // Test 1: Initialize project
    test(`${pm}: Initialize project`, () => {
      const initCmd = pm === 'npm' ? 'npm init -y' : 'pnpm init';
      const result = exec(initCmd, { cwd: testDir });
      if (!result.success) {
        console.log(`    ❌ FAIL: ${result.error}`);
        return false;
      }

      const packageJsonExists = fs.existsSync(path.join(testDir, 'package.json'));
      if (packageJsonExists) {
        console.log(`    ✅ PASS: Project initialized`);
        return true;
      }
      console.log(`    ❌ FAIL: package.json not created`);
      return false;
    });

    // Test 2: Add dependencies
    const depsStr = TEST_DEPENDENCIES.join(', ');
    test(`${pm}: Add dependencies (${depsStr})`, () => {
      const depsList = TEST_DEPENDENCIES.join(' ');
      const addCmd = pm === 'npm'
        ? `npm install ${depsList}`
        : `pnpm add ${depsList}`;
      const result = exec(addCmd, { cwd: testDir });
      if (!result.success) {
        console.log(`    ❌ FAIL: ${result.error}`);
        return false;
      }

      // Verify dependencies were added to package.json
      const packageJson = JSON.parse(fs.readFileSync(path.join(testDir, 'package.json'), 'utf8'));
      const missingDeps = TEST_DEPENDENCIES.filter(
        dep => !packageJson.dependencies || !packageJson.dependencies[dep]
      );
      if (missingDeps.length === 0) {
        console.log(`    ✅ PASS: Dependencies added`);
        return true;
      }
      console.log(`    ❌ FAIL: Missing dependencies in package.json: ${missingDeps.join(', ')}`);
      return false;
    });

    // Test 3: Verify node_modules exists
    test(`${pm}: Verify node_modules created`, () => {
      const nodeModulesExists = fs.existsSync(path.join(testDir, 'node_modules'));
      if (!nodeModulesExists) {
        console.log(`    ❌ FAIL: node_modules missing`);
        return false;
      }
      const missingDeps = TEST_DEPENDENCIES.filter(
        dep => !fs.existsSync(path.join(testDir, 'node_modules', dep))
      );
      if (missingDeps.length === 0) {
        console.log(`    ✅ PASS: node_modules and dependencies exist`);
        return true;
      }
      console.log(`    ❌ FAIL: Missing in node_modules: ${missingDeps.join(', ')}`);
      return false;
    });

    // Test 4: Clean install (remove node_modules and reinstall)
    test(`${pm}: Clean install`, () => {
      // Remove node_modules
      const nodeModulesPath = path.join(testDir, 'node_modules');
      fs.rmSync(nodeModulesPath, { recursive: true, force: true });

      // Reinstall
      const installCmd = pm === 'npm' ? 'npm install' : 'pnpm install';
      const result = exec(installCmd, { cwd: testDir });
      if (!result.success) {
        console.log(`    ❌ FAIL: ${result.error}`);
        return false;
      }

      // Verify node_modules recreated with all dependencies
      const missingDeps = TEST_DEPENDENCIES.filter(
        dep => !fs.existsSync(path.join(testDir, 'node_modules', dep))
      );
      if (missingDeps.length === 0) {
        console.log(`    ✅ PASS: Clean install successful`);
        return true;
      }
      console.log(`    ❌ FAIL: Dependencies not reinstalled: ${missingDeps.join(', ')}`);
      return false;
    });

  } finally {
    cleanup(testDir);
    console.log(`  Cleaned up: ${testDir}`);
  }
}

// Main
console.log('=== PMG Package Manager E2E Tests ===\n');
console.log('This script tests basic npm/pnpm flows to ensure sandbox compatibility.\n');

for (const pm of PACKAGE_MANAGERS) {
  // Check if package manager is available
  const checkResult = exec(`which ${pm}`);
  if (!checkResult.success) {
    console.log(`--- Skipping ${pm} (not installed) ---`);
    continue;
  }

  console.log(`--- Testing ${pm.toUpperCase()} ---`);
  testPackageManager(pm);
}

// Summary
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

console.log('\nAll tests passed!');
