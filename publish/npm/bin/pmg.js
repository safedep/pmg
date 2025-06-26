#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { spawn } = require("child_process");

const BINARY_NAME = process.platform === "win32" ? "pmg.exe" : "pmg";
const BINARY_PATH = path.join(__dirname, BINARY_NAME);

function main() {
  // Check if binary exists
  if (!fs.existsSync(BINARY_PATH)) {
    console.error(
      `❌ Error: ${BINARY_NAME} binary not found at ${BINARY_PATH}`,
    );
    console.error("");
    console.error("This usually means:");
    console.error("  1. The installation failed or was incomplete");
    console.error("  2. Your platform is not supported");
    console.error(
      `  3. Expected binary for: ${process.platform}-${process.arch}`,
    );
    console.error("");
    console.error("Try reinstalling the package:");
    console.error("  npm uninstall -g @safedep/pmg");
    console.error("  npm cache clean --force");
    console.error("  npm install -g @safedep/pmg");
    console.error("");
    console.error("If the problem persists, please report an issue at:");
    console.error("  https://github.com/safedep/pmg/issues");
    process.exit(1);
  }

  // Verify binary is executable
  try {
    fs.accessSync(BINARY_PATH, fs.constants.F_OK | fs.constants.X_OK);
  } catch (error) {
    console.error(
      `❌ Error: ${BINARY_NAME} binary is not executable: ${error.message}`,
    );
    console.error("");
    console.error("This could be due to:");
    console.error("  1. File permissions issue");
    console.error("  2. Corrupted binary during installation");
    console.error("  3. Antivirus software blocking the binary");
    console.error("");
    console.error("Try reinstalling the package:");
    console.error("  npm uninstall -g @safedep/pmg");
    console.error("  npm install -g @safedep/pmg");
    process.exit(1);
  }

  // Pass all arguments to the binary
  const args = process.argv.slice(2);

  // Spawn the binary with inherited stdio for proper terminal interaction
  const child = spawn(BINARY_PATH, args, {
    stdio: "inherit",
    windowsHide: false,
  });

  // Handle process termination
  child.on("error", (error) => {
    if (error.code === "ENOENT") {
      console.error(`❌ Error: Could not execute ${BINARY_NAME}`);
      console.error(
        "The binary may be corrupted or missing. Try reinstalling the package.",
      );
    } else if (error.code === "EACCES") {
      console.error(`❌ Error: Permission denied executing ${BINARY_NAME}`);
      console.error("The binary may not have execute permissions.");
    } else {
      console.error(`❌ Error executing ${BINARY_NAME}: ${error.message}`);
    }
    console.error("");
    console.error("Try reinstalling:");
    console.error(
      "  npm uninstall -g @safedep/pmg && npm install -g @safedep/pmg",
    );
    process.exit(1);
  });

  // Exit with the same code as the child process
  child.on("exit", (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
    } else {
      process.exit(code || 0);
    }
  });

  // Handle termination signals
  process.on("SIGTERM", () => {
    child.kill("SIGTERM");
  });

  process.on("SIGINT", () => {
    child.kill("SIGINT");
  });
}

if (require.main === module) {
  main();
}

module.exports = { main };
