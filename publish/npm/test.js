#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");
const {
  ORG_NAME,
  PACKAGE_NAME,
  BINARY_NAME,
  REPO_OWNER,
  REPO_NAME,
  GITHUB_RELEASES_BASE,
  BINARY_PATTERNS,
} = require("./config");

// Colors for terminal output
const colors = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
};

function log(message, color = "reset") {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function logError(message) {
  log(`❌ ${message}`, "red");
}

function logSuccess(message) {
  log(`✅ ${message}`, "green");
}

function logInfo(message) {
  log(`ℹ️  ${message}`, "blue");
}

function logWarning(message) {
  log(`⚠️  ${message}`, "yellow");
}

async function runTest(name, testFn) {
  try {
    log(`\n🧪 Testing: ${name}`, "cyan");
    await testFn();
    logSuccess(`Test passed: ${name}`);
    return true;
  } catch (error) {
    logError(`Test failed: ${name}`);
    logError(`Error: ${error.message}`);
    return false;
  }
}

function validateConfig() {
  const configPath = path.join(__dirname, "config.js");

  if (!fs.existsSync(configPath)) {
    throw new Error("config.js file not found");
  }

  // Validate required config constants
  const requiredConstants = [
    "ORG_NAME",
    "PACKAGE_NAME",
    "BINARY_NAME",
    "REPO_OWNER",
    "REPO_NAME",
    "GITHUB_RELEASES_BASE",
    "BINARY_PATTERNS",
  ];

  for (const constant of requiredConstants) {
    if (!constant) {
      throw new Error(`Missing config constant: ${constant}`);
    }
  }

  // Validate config values
  if (!ORG_NAME.startsWith("@")) {
    throw new Error("ORG_NAME must start with @");
  }

  if (
    !GITHUB_RELEASES_BASE.includes(REPO_OWNER) ||
    !GITHUB_RELEASES_BASE.includes(REPO_NAME)
  ) {
    throw new Error(
      "GITHUB_RELEASES_BASE must contain REPO_OWNER and REPO_NAME",
    );
  }

  // Validate platform patterns
  const expectedPlatforms = [
    "darwin-x64",
    "darwin-arm64",
    "linux-x64",
    "linux-arm64",
    "linux-ia32",
    "win32-x64",
    "win32-arm64",
    "win32-ia32",
  ];

  for (const platform of expectedPlatforms) {
    if (!BINARY_PATTERNS[platform]) {
      throw new Error(`Missing binary pattern for platform: ${platform}`);
    }
  }

  logInfo(`Package: ${ORG_NAME}/${PACKAGE_NAME}`);
  logInfo(`Binary: ${BINARY_NAME}`);
  logInfo(`Repository: ${REPO_OWNER}/${REPO_NAME}`);
  logInfo(`Platforms: ${Object.keys(BINARY_PATTERNS).length}`);
}

function validatePackageJson() {
  const packagePath = path.join(__dirname, "package.json");
  const packageJson = JSON.parse(fs.readFileSync(packagePath, "utf8"));

  // Check required fields
  const requiredFields = ["name", "version", "description", "main", "bin"];
  for (const field of requiredFields) {
    if (!packageJson[field]) {
      throw new Error(`Missing required field: ${field}`);
    }
  }

  // Validate name matches config
  if (packageJson.name !== `${ORG_NAME}/${PACKAGE_NAME}`) {
    throw new Error(
      `package.json name doesn't match config: expected ${ORG_NAME}/${PACKAGE_NAME}, got ${packageJson.name}`,
    );
  }

  // Check bin configuration
  if (!packageJson.bin[PACKAGE_NAME]) {
    throw new Error(`Missing bin.${PACKAGE_NAME} configuration`);
  }

  // Check if bin file exists
  const binPath = path.join(__dirname, packageJson.bin[PACKAGE_NAME]);
  if (!fs.existsSync(binPath)) {
    throw new Error(
      `Bin file does not exist: ${packageJson.bin[PACKAGE_NAME]}`,
    );
  }

  // Check supported platforms
  const supportedOs = ["darwin", "linux", "win32"];
  const supportedCpu = ["x64", "arm64", "ia32"];

  if (!packageJson.os || !Array.isArray(packageJson.os)) {
    throw new Error("Missing or invalid os field");
  }

  if (!packageJson.cpu || !Array.isArray(packageJson.cpu)) {
    throw new Error("Missing or invalid cpu field");
  }

  for (const os of packageJson.os) {
    if (!supportedOs.includes(os)) {
      throw new Error(`Unsupported OS: ${os}`);
    }
  }

  for (const cpu of packageJson.cpu) {
    if (!supportedCpu.includes(cpu)) {
      throw new Error(`Unsupported CPU: ${cpu}`);
    }
  }

  logInfo(`Package name: ${packageJson.name}`);
  logInfo(`Version: ${packageJson.version}`);
  logInfo(`Supported OS: ${packageJson.os.join(", ")}`);
  logInfo(`Supported CPU: ${packageJson.cpu.join(", ")}`);
}

function validateFiles() {
  const packagePath = path.join(__dirname, "package.json");
  const packageJson = JSON.parse(fs.readFileSync(packagePath, "utf8"));

  // Check all files listed in package.json exist
  if (packageJson.files) {
    for (const file of packageJson.files) {
      const filePath = path.join(__dirname, file);
      if (!fs.existsSync(filePath)) {
        throw new Error(`File listed in package.json does not exist: ${file}`);
      }
    }
  }

  // Check essential files
  const essentialFiles = ["install.js", "config.js", "bin/pmg.js", "README.md"];
  for (const file of essentialFiles) {
    const filePath = path.join(__dirname, file);
    if (!fs.existsSync(filePath)) {
      throw new Error(`Essential file missing: ${file}`);
    }
  }

  // Check .npmignore
  const npmIgnorePath = path.join(__dirname, ".npmignore");
  if (!fs.existsSync(npmIgnorePath)) {
    logWarning(".npmignore file not found");
  }
}

function validateInstallScript() {
  const installPath = path.join(__dirname, "install.js");
  const installScript = fs.readFileSync(installPath, "utf8");

  // Check for required functions
  const requiredFunctions = [
    "getValidatedVersion",
    "getPlatformKey",
    "downloadFile",
    "calculateChecksum",
    "validateChecksum",
    "extractArchive",
    "install",
  ];

  for (const func of requiredFunctions) {
    if (!installScript.includes(`function ${func}`)) {
      throw new Error(`Missing required function: ${func}`);
    }
  }

  // Check for config import
  if (!installScript.includes('require("./config")')) {
    throw new Error("Missing config import");
  }

  // Check for package.json version handling
  if (!installScript.includes("package.json")) {
    throw new Error("Missing package.json version handling");
  }

  // Check for checksum validation
  if (!installScript.includes("validateChecksum")) {
    throw new Error("Missing checksum validation");
  }

  // Check for strict version validation
  if (!installScript.includes("Invalid version format")) {
    throw new Error("Missing strict version validation");
  }

  // Check for hardcoded GitHub base URL usage
  if (!installScript.includes("GITHUB_RELEASES_BASE")) {
    throw new Error("Missing GitHub releases base URL from config");
  }
}

function validateBinScript() {
  const binPath = path.join(__dirname, "bin/pmg.js");
  const binScript = fs.readFileSync(binPath, "utf8");

  // Check shebang
  if (!binScript.startsWith("#!/usr/bin/env node")) {
    throw new Error("Missing or incorrect shebang in bin script");
  }

  // Check for config import
  if (!binScript.includes('require("../config")')) {
    throw new Error("Missing config import in bin script");
  }

  // Check for required functionality
  const requiredPatterns = [
    "spawn",
    'stdio: "inherit"',
    "BINARY_NAME",
    "BINARY_PATH",
    "ORG_NAME",
    "PACKAGE_NAME",
  ];

  for (const pattern of requiredPatterns) {
    if (!binScript.includes(pattern)) {
      throw new Error(`Missing required pattern in bin script: ${pattern}`);
    }
  }

  // Check file permissions
  try {
    fs.accessSync(binPath, fs.constants.X_OK);
  } catch (error) {
    // This might not work on all systems, so just warn
    logWarning("Bin script may not be executable");
  }
}

function testPlatformSupport() {
  // Test current platform is supported
  const currentPlatform = process.platform;
  const currentArch = process.arch;
  const platformKey = `${currentPlatform}-${currentArch}`;

  logInfo(`Current platform: ${platformKey}`);

  if (!BINARY_PATTERNS[platformKey]) {
    throw new Error(`Current platform not supported: ${platformKey}`);
  }

  // Validate all platform patterns have correct binary name
  for (const [platform, pattern] of Object.entries(BINARY_PATTERNS)) {
    if (!pattern.includes(BINARY_NAME)) {
      throw new Error(
        `Binary pattern for ${platform} doesn't include binary name: ${pattern}`,
      );
    }
  }

  logInfo(`✅ Platform ${platformKey} is supported`);
  logInfo(`Binary pattern: ${BINARY_PATTERNS[platformKey]}`);
}

function testVersionHandling() {
  const installPath = path.join(__dirname, "install.js");
  const installScript = fs.readFileSync(installPath, "utf8");

  // Check for version validation logic
  if (!installScript.includes("getValidatedVersion")) {
    throw new Error("Version validation function not found");
  }

  // Check for semver validation
  if (!installScript.includes("/^\\d+\\.\\d+\\.\\d+$/")) {
    throw new Error("Missing semver validation regex");
  }

  // Test version reading from package.json
  try {
    const packageJson = JSON.parse(
      fs.readFileSync(path.join(__dirname, "package.json"), "utf8"),
    );

    const version = packageJson.version;
    if (!/^\d+\.\d+\.\d+$/.test(version)) {
      throw new Error(`Package.json version is not valid semver: ${version}`);
    }

    logInfo(`Package version: ${version}`);
  } catch (error) {
    throw new Error(`Failed to test version reading: ${error.message}`);
  }
}

async function testNpmPack() {
  try {
    // Test npm pack --dry-run
    const result = execSync("npm pack --dry-run --verbose", {
      cwd: __dirname,
      stdio: "pipe",
      encoding: "utf8",
    });

    logInfo("npm pack --dry-run completed successfully");

    // Get list of files that would be packaged
    const lines = result.split("\n");
    const fileLines = lines.filter(
      (line) =>
        line.trim() && !line.includes("npm notice") && !line.includes(".tgz"),
    );

    // Check if essential files are included
    const essentialFiles = [
      "install.js",
      "config.js",
      "bin/pmg.js",
      "package.json",
    ];
    for (const file of essentialFiles) {
      const found = fileLines.some((line) => line.includes(file));
      if (!found) {
        logWarning(`File may not be included in package: ${file}`);
      }
    }

    logInfo(`Package would contain ${fileLines.length} files`);
  } catch (error) {
    throw new Error(`npm pack failed: ${error.message}`);
  }
}

function testSecurityFeatures() {
  const installPath = path.join(__dirname, "install.js");
  const installScript = fs.readFileSync(installPath, "utf8");

  // Check for security features
  const securityFeatures = [
    "calculateChecksum",
    "validateChecksum",
    "sha256",
    "Invalid version format",
    "Checksum validation failed",
  ];

  for (const feature of securityFeatures) {
    if (!installScript.includes(feature)) {
      throw new Error(`Missing security feature: ${feature}`);
    }
  }

  // Ensure no dynamic URL construction from external input
  if (installScript.includes("process.env.GITHUB_REF")) {
    throw new Error(
      "Found dangerous dynamic URL construction from environment variables",
    );
  }

  // Check that URLs are constructed from hardcoded config
  if (!installScript.includes("GITHUB_RELEASES_BASE")) {
    throw new Error("URLs not constructed from hardcoded config base");
  }

  logInfo("✅ Security features validated");
}

async function main() {
  log("🚀 Starting npm package validation tests", "magenta");

  let passed = 0;
  let failed = 0;

  const tests = [
    ["Configuration validation", validateConfig],
    ["Package.json validation", validatePackageJson],
    ["File structure validation", validateFiles],
    ["Install script validation", validateInstallScript],
    ["Bin script validation", validateBinScript],
    ["Platform support test", testPlatformSupport],
    ["Version handling test", testVersionHandling],
    ["Security features test", testSecurityFeatures],
    ["npm pack test", testNpmPack],
  ];

  for (const [name, testFn] of tests) {
    const success = await runTest(name, testFn);
    if (success) {
      passed++;
    } else {
      failed++;
    }
  }

  log("\n📊 Test Results:", "magenta");
  logSuccess(`Passed: ${passed}`);
  if (failed > 0) {
    logError(`Failed: ${failed}`);
  }

  if (failed === 0) {
    log("\n🎉 All tests passed! Package is ready for publishing.", "green");
    process.exit(0);
  } else {
    log(
      "\n💥 Some tests failed. Please fix the issues before publishing.",
      "red",
    );
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((error) => {
    logError(`Test runner failed: ${error.message}`);
    process.exit(1);
  });
}

module.exports = { main };
