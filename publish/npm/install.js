#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const https = require("https");
const { execSync } = require("child_process");

// GitHub release info
const BINARY_NAME = "pmg";

// Platform and architecture mapping
function getPlatformInfo() {
  const platform = process.platform;
  const arch = process.arch;

  let platformName,
    archName,
    extension,
    isZip = false;

  // Map Node.js platform to release naming (matching GoReleaser output)
  switch (platform) {
    case "darwin":
      platformName = "Darwin_all";
      extension = ".tar.gz";
      break;
    case "linux":
      platformName = "Linux";
      extension = ".tar.gz";
      break;
    case "win32":
      platformName = "Windows";
      extension = ".zip";
      isZip = true;
      break;
    default:
      throw new Error(`Unsupported platform: ${platform}`);
  }

  // Map Node.js arch to release naming
  switch (arch) {
    case "x64":
      archName = "x86_64";
      break;
    case "arm64":
      archName = "arm64";
      break;
    case "ia32":
      archName = "i386";
      break;
    default:
      throw new Error(`Unsupported architecture: ${arch}`);
  }

  // Special case for Darwin - it's all architectures in one
  if (platform === "darwin") {
    return {
      filename: `pmg_${platformName}${extension}`,
      isZip,
      extension,
    };
  }

  return {
    filename: `pmg_${platformName}_${archName}${extension}`,
    isZip,
    extension,
  };
}

// Download file from URL
function downloadFile(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);

    https
      .get(url, (response) => {
        if (response.statusCode === 302 || response.statusCode === 301) {
          // Handle redirect
          return downloadFile(response.headers.location, dest)
            .then(resolve)
            .catch(reject);
        }

        if (response.statusCode !== 200) {
          reject(new Error(`Failed to download: ${response.statusCode}`));
          return;
        }

        response.pipe(file);

        file.on("finish", () => {
          file.close();
          resolve();
        });

        file.on("error", (err) => {
          fs.unlink(dest, () => {}); // Delete the file on error
          reject(err);
        });
      })
      .on("error", reject);
  });
}

// Extract archive using system commands
function extractArchive(archivePath, extractDir, isZip) {
  try {
    if (isZip) {
      // Use system unzip command
      execSync(`unzip -o "${archivePath}" -d "${extractDir}"`, {
        stdio: "pipe",
      });
    } else {
      // Use system tar command
      execSync(`tar -xzf "${archivePath}" -C "${extractDir}"`, {
        stdio: "pipe",
      });
    }
    console.log("✅ Extraction completed using system commands");
  } catch (error) {
    console.log("❌ System extraction failed, trying Node.js tar library...");

    // Fallback to tar library
    try {
      const tar = require("tar");
      return tar.x({
        file: archivePath,
        cwd: extractDir,
        strip: 0,
      });
    } catch (tarError) {
      throw new Error(
        `Both system extraction and tar library failed. System: ${error.message}, Tar: ${tarError.message}. You may need to install the 'tar' package or ensure system tar/unzip commands are available.`,
      );
    }
  }
}

// Make file executable (Unix systems)
function makeExecutable(filePath) {
  if (process.platform !== "win32") {
    fs.chmodSync(filePath, "755");
  }
}

// Validate binary after installation
function validateBinary(binaryPath) {
  try {
    // Try to run the binary with version command to verify it works
    const result = execSync(`"${binaryPath}" version`, {
      stdio: "pipe",
      timeout: 5000, // 5 second timeout
    });
    console.log(`✅ Binary validation successful: ${result.toString().trim()}`);
    return true;
  } catch (error) {
    console.warn(`⚠️  Binary validation failed: ${error.message}`);
    console.warn("The binary was installed but may not work correctly.");
    return false;
  }
}

// Get version from GitHub environment variable or fallback to package.json
function getVersion() {
  // Try to get version from GitHub environment variables
  // GITHUB_REF_NAME contains just the tag name (e.g., "v1.0.0")
  // GITHUB_REF contains the full ref (e.g., "refs/tags/v1.0.0")
  let version = process.env.GITHUB_REF_NAME || process.env.GITHUB_REF;

  if (version) {
    // If GITHUB_REF, extract tag name from "refs/tags/v1.0.0"
    if (version.startsWith("refs/tags/")) {
      version = version.replace("refs/tags/", "");
    }

    // Ensure version starts with 'v'
    if (!version.startsWith("v")) {
      version = `v${version}`;
    }

    console.log(`📌 Using version from GitHub environment: ${version}`);
    return version;
  }

  // Fallback to package.json
  try {
    const packageJson = JSON.parse(
      fs.readFileSync(path.join(__dirname, "package.json"), "utf8"),
    );
    const fallbackVersion = `v${packageJson.version}`;
    console.log(
      `📌 Using fallback version from package.json: ${fallbackVersion}`,
    );
    return fallbackVersion;
  } catch (error) {
    throw new Error(
      `Failed to read version from environment or package.json: ${error.message}`,
    );
  }
}

// Get release info for specific version from GitHub API
function getReleaseByTag(tag) {
  const releaseUrl = `https://api.github.com/repos/safedep/pmg/releases/tags/${tag}`;

  return new Promise((resolve, reject) => {
    https
      .get(
        releaseUrl,
        {
          headers: {
            "User-Agent": "pmg-npm-installer",
          },
        },
        (response) => {
          let data = "";

          response.on("data", (chunk) => {
            data += chunk;
          });

          response.on("end", () => {
            try {
              if (response.statusCode === 404) {
                reject(new Error(`Release ${tag} not found`));
                return;
              }
              if (response.statusCode !== 200) {
                reject(
                  new Error(
                    `Failed to fetch release info: ${response.statusCode}`,
                  ),
                );
                return;
              }
              const release = JSON.parse(data);
              resolve(release);
            } catch (err) {
              reject(new Error(`Failed to parse release info: ${err.message}`));
            }
          });
        },
      )
      .on("error", reject);
  });
}

async function install() {
  try {
    console.log("📦 Installing PMG binary...");

    // Get platform info
    const platformInfo = getPlatformInfo();
    console.log(`🔍 Detected platform: ${process.platform}-${process.arch}`);
    console.log(`📋 Looking for: ${platformInfo.filename}`);

    // Get version from GitHub environment variable or fallback to package.json
    const version = getVersion();
    console.log(`📡 Installing version: ${version}`);

    // Get release info for the specific version
    const release = await getReleaseByTag(version);
    console.log(`📡 Found release: ${release.tag_name}`);

    // Find the asset for our platform
    const asset = release.assets.find(
      (asset) => asset.name === platformInfo.filename,
    );
    if (!asset) {
      console.log("🔍 Available assets:");
      release.assets.forEach((asset) => {
        console.log(`  - ${asset.name}`);
      });
      throw new Error(`No binary found for platform ${platformInfo.filename}`);
    }

    // Create directories
    const binDir = path.join(__dirname, "..", "bin");
    const tempDir = path.join(__dirname, "..", "temp");

    if (!fs.existsSync(binDir)) {
      fs.mkdirSync(binDir, { recursive: true });
    }
    if (!fs.existsSync(tempDir)) {
      fs.mkdirSync(tempDir, { recursive: true });
    }

    // Download the binary
    const archivePath = path.join(tempDir, platformInfo.filename);
    console.log(`⬇️  Downloading ${asset.browser_download_url}`);
    console.log(`📁 Saving to: ${archivePath}`);
    await downloadFile(asset.browser_download_url, archivePath);

    // Verify download
    const stats = fs.statSync(archivePath);
    console.log(`📊 Downloaded ${stats.size} bytes (expected: ${asset.size})`);

    if (stats.size !== asset.size) {
      throw new Error(
        `Download size mismatch. Expected ${asset.size}, got ${stats.size}`,
      );
    }

    // Extract the archive
    console.log("📂 Extracting binary...");
    try {
      await extractArchive(archivePath, tempDir, platformInfo.isZip);
    } catch (error) {
      throw new Error(`Failed to extract archive: ${error.message}`);
    }

    // Find the binary in extracted files - search for it recursively
    const binaryExtension = process.platform === "win32" ? ".exe" : "";
    const expectedBinaryName = BINARY_NAME + binaryExtension;

    let extractedBinaryPath = null;

    // Look for the binary in the temp directory and subdirectories
    function findBinary(dir) {
      const files = fs.readdirSync(dir);
      for (const file of files) {
        const fullPath = path.join(dir, file);
        const stat = fs.statSync(fullPath);

        if (stat.isDirectory()) {
          const found = findBinary(fullPath);
          if (found) return found;
        } else if (file === expectedBinaryName) {
          return fullPath;
        }
      }
      return null;
    }

    extractedBinaryPath = findBinary(tempDir);

    if (!extractedBinaryPath) {
      // List all files in temp directory for debugging
      console.log("🔍 Files in extracted archive:");
      function listFiles(dir, prefix = "") {
        const files = fs.readdirSync(dir);
        files.forEach((file) => {
          const fullPath = path.join(dir, file);
          const stat = fs.statSync(fullPath);
          if (stat.isDirectory()) {
            console.log(`${prefix}📁 ${file}/`);
            listFiles(fullPath, prefix + "  ");
          } else {
            console.log(`${prefix}📄 ${file}`);
          }
        });
      }
      listFiles(tempDir);

      throw new Error(
        `Binary '${expectedBinaryName}' not found in extracted archive`,
      );
    }

    console.log(`✅ Found binary at: ${extractedBinaryPath}`);

    const finalBinaryPath = path.join(binDir, expectedBinaryName);

    // Move binary to bin directory
    fs.renameSync(extractedBinaryPath, finalBinaryPath);

    // Make executable
    makeExecutable(finalBinaryPath);

    // Validate binary works
    const isValid = validateBinary(finalBinaryPath);
    if (!isValid) {
      throw new Error(`Validation failed for binary at: ${finalBinaryPath}`);
    }
    // Clean up
    fs.rmSync(tempDir, { recursive: true, force: true });

    console.log("✅ PMG binary installed successfully!");
    console.log("🚀 You can now use: pmg --help");
  } catch (error) {
    console.error("❌ Installation failed:", error.message);

    // Clean up on failure
    try {
      const tempDir = path.join(__dirname, "..", "temp");
      if (fs.existsSync(tempDir)) {
        fs.rmSync(tempDir, { recursive: true, force: true });
      }
    } catch (cleanupError) {
      console.warn(
        "⚠️  Failed to clean up temporary files:",
        cleanupError.message,
      );
    }

    process.exit(1);
  }
}

// Run installation
install();
