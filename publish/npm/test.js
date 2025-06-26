#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

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

  // Check bin configuration
  if (!packageJson.bin.pmg) {
    throw new Error("Missing bin.pmg configuration");
  }

  // Check if bin file exists
  const binPath = path.join(__dirname, packageJson.bin.pmg);
  if (!fs.existsSync(binPath)) {
    throw new Error(`Bin file does not exist: ${packageJson.bin.pmg}`);
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
  const essentialFiles = ["install.js", "bin/pmg.js", "README.md"];
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
    "getPlatformInfo",
    "downloadFile",
    "extractArchive",
    "getVersion",
    "getReleaseByTag",
    "install",
  ];

  for (const func of requiredFunctions) {
    if (!installScript.includes(`function ${func}`)) {
      throw new Error(`Missing required function: ${func}`);
    }
  }

  // Check for GitHub environment variable support
  if (!installScript.includes("GITHUB_REF_NAME")) {
    throw new Error("Missing GitHub environment variable support");
  }

  // Check for proper platform mapping
  const platforms = ["darwin", "linux", "win32"];
  for (const platform of platforms) {
    if (!installScript.includes(`case "${platform}"`)) {
      throw new Error(`Missing platform support: ${platform}`);
    }
  }
}

function validateBinScript() {
  const binPath = path.join(__dirname, "bin/pmg.js");
  const binScript = fs.readFileSync(binPath, "utf8");

  // Check shebang
  if (!binScript.startsWith("#!/usr/bin/env node")) {
    throw new Error("Missing or incorrect shebang in bin script");
  }

  // Check for required functionality
  const requiredPatterns = [
    "spawn",
    'stdio: "inherit"',
    "BINARY_NAME",
    "BINARY_PATH",
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

function testPlatformDetection() {
  // Test platform info function by requiring the install script
  const installPath = path.join(__dirname, "install.js");

  // Read and extract the getPlatformInfo function
  const installScript = fs.readFileSync(installPath, "utf8");

  // This is a basic test - in a real scenario we'd properly extract the function
  if (!installScript.includes("getPlatformInfo")) {
    throw new Error("getPlatformInfo function not found");
  }

  // Test current platform
  const currentPlatform = process.platform;
  const currentArch = process.arch;

  logInfo(`Current platform: ${currentPlatform}-${currentArch}`);

  const supportedPlatforms = {
    darwin: ["x64", "arm64"],
    linux: ["x64", "arm64", "ia32"],
    win32: ["x64", "arm64", "ia32"],
  };

  if (!supportedPlatforms[currentPlatform]) {
    throw new Error(`Unsupported platform: ${currentPlatform}`);
  }

  if (!supportedPlatforms[currentPlatform].includes(currentArch)) {
    throw new Error(
      `Unsupported architecture for ${currentPlatform}: ${currentArch}`,
    );
  }
}

function testVersionHandling() {
  const installPath = path.join(__dirname, "install.js");
  const installScript = fs.readFileSync(installPath, "utf8");

  // Check for version handling logic
  if (!installScript.includes("getVersion")) {
    throw new Error("Version handling function not found");
  }

  // Check for GitHub environment variable handling
  if (
    !installScript.includes("GITHUB_REF_NAME") ||
    !installScript.includes("GITHUB_REF")
  ) {
    throw new Error("Missing GitHub environment variable handling");
  }

  // Check for package.json fallback
  if (!installScript.includes("package.json")) {
    throw new Error("Missing package.json fallback");
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

    logInfo("npm pack --dry-run output:");
    console.log(result);

    // Get list of files that would be packaged
    const lines = result.split("\n");
    const fileLines = lines.filter(
      (line) =>
        line.trim() && !line.includes("npm notice") && !line.includes(".tgz"),
    );

    // Check if essential files are included
    const essentialFiles = ["install.js", "bin/pmg.js", "package.json"];
    for (const file of essentialFiles) {
      const found = fileLines.some((line) => line.includes(file));
      if (!found) {
        logWarning(`File may not be included in package: ${file}`);
        logInfo("Files found in package:");
        fileLines.forEach((line) => logInfo(`  ${line.trim()}`));
      }
    }

    logInfo(`Package would contain ${fileLines.length} files`);
  } catch (error) {
    throw new Error(`npm pack failed: ${error.message}`);
  }
}

async function main() {
  log("🚀 Starting PMG npm package validation tests", "magenta");

  let passed = 0;
  let failed = 0;

  const tests = [
    ["Package.json validation", validatePackageJson],
    ["File structure validation", validateFiles],
    ["Install script validation", validateInstallScript],
    ["Bin script validation", validateBinScript],
    ["Platform detection test", testPlatformDetection],
    ["Version handling test", testVersionHandling],
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
