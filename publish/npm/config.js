// Configuration for npm binary wrapper

const ORG_NAME = "@safedep";
const PACKAGE_NAME = "pmg";
const BINARY_NAME = "pmg";

// GitHub repository information for releases
const REPO_OWNER = "safedep";
const REPO_NAME = "pmg";

// GitHub releases base URL (constructed from repo info)
const GITHUB_RELEASES_BASE = `https://github.com/${REPO_OWNER}/${REPO_NAME}/releases/download`;

// Platform-specific binary filename patterns (GoReleaser format)
const BINARY_PATTERNS = {
  "darwin-x64": `${BINARY_NAME}_Darwin_all.tar.gz`,
  "darwin-arm64": `${BINARY_NAME}_Darwin_all.tar.gz`,
  "linux-x64": `${BINARY_NAME}_Linux_x86_64.tar.gz`,
  "linux-arm64": `${BINARY_NAME}_Linux_arm64.tar.gz`,
  "linux-ia32": `${BINARY_NAME}_Linux_i386.tar.gz`,
  "win32-x64": `${BINARY_NAME}_Windows_x86_64.zip`,
  "win32-arm64": `${BINARY_NAME}_Windows_arm64.zip`,
  "win32-ia32": `${BINARY_NAME}_Windows_i386.zip`,
};

module.exports = {
  ORG_NAME,
  PACKAGE_NAME,
  BINARY_NAME,
  REPO_OWNER,
  REPO_NAME,
  GITHUB_RELEASES_BASE,
  BINARY_PATTERNS,
};
