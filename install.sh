#!/bin/sh
set -eu

do_install() {
  REPO="safedep/pmg"
  BINARY="pmg"

  # Prefer $HOME/.local/bin if it exists and is in PATH.
  INSTALL_DIR="/usr/local/bin"
  if [ -n "${HOME:-}" ]; then
    local_bin="$HOME/.local/bin"
    case ":${PATH}:" in
    *":${local_bin}:"*)
      INSTALL_DIR="$local_bin"
      mkdir -p "$INSTALL_DIR"
      ;;
    esac
  fi

  # Detect OS and architecture.
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
  Linux) os="Linux" ;;
  Darwin) os="Darwin" ;;
  MINGW* | MSYS* | CYGWIN*) os="Windows" ;;
  *)
    echo "Error: unsupported operating system: $OS" >&2
    exit 1
    ;;
  esac

  case "$ARCH" in
  x86_64 | amd64) arch="x86_64" ;;
  aarch64 | arm64) arch="arm64" ;;
  i386 | i686) arch="i386" ;;
  *)
    echo "Error: unsupported architecture: $ARCH" >&2
    exit 1
    ;;
  esac

  # macOS ships a universal binary.
  if [ "$os" = "Darwin" ]; then
    arch="all"
  fi

  if [ "$os" = "Windows" ]; then
    BINARY="pmg.exe"
  fi

  # Verify install directory exists.
  if [ ! -d "$INSTALL_DIR" ]; then
    echo "Error: install directory ${INSTALL_DIR} does not exist" >&2
    echo "Create it with: sudo mkdir -p ${INSTALL_DIR}" >&2
    exit 1
  fi

  # Fetch latest release tag via redirect (avoids JSON parsing).
  echo "Fetching latest release..."
  tag=$(curl -fsSI -o /dev/null -w '%{redirect_url}' "https://github.com/${REPO}/releases/latest" | sed 's|.*/||')
  if [ -z "$tag" ]; then
    echo "Error: could not determine latest release" >&2
    exit 1
  fi
  echo "Latest release: $tag"

  # Build download URL.
  # Assets follow the pattern: pmg_{OS}_{arch}.{tar.gz|zip}
  if [ "$os" = "Windows" ]; then
    asset="pmg_${os}_${arch}.zip"
  else
    asset="pmg_${os}_${arch}.tar.gz"
  fi
  url="https://github.com/${REPO}/releases/download/${tag}/${asset}"

  # Download archive and checksums.
  echo "Downloading ${asset}..."
  tmpdir=$(mktemp -d)
  trap 'rm -rf "$tmpdir"' EXIT
  checksums_url="https://github.com/${REPO}/releases/download/${tag}/checksums.txt"
  if ! curl -fsSL -o "${tmpdir}/${asset}" "$url"; then
    echo "Error: archive not available for ${os}/${arch}" >&2
    echo "Check available assets at https://github.com/${REPO}/releases/tag/${tag}" >&2
    exit 1
  fi
  if ! curl -fsSL -o "${tmpdir}/checksums.txt" "$checksums_url"; then
    echo "Error: could not download checksums.txt from ${checksums_url}" >&2
    exit 1
  fi

  # Verify SHA-256 checksum.
  expected=$(grep "  ${asset}$" "${tmpdir}/checksums.txt" | cut -d' ' -f1)
  if [ -z "$expected" ]; then
    echo "Error: no checksum entry found for ${asset} in checksums.txt" >&2
    exit 1
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "${tmpdir}/${asset}" | cut -d' ' -f1)
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "${tmpdir}/${asset}" | cut -d' ' -f1)
  else
    echo "Error: neither sha256sum nor shasum found; cannot verify download" >&2
    echo "       Install one of them and re-run, or download manually from:" >&2
    echo "       https://github.com/${REPO}/releases/tag/${tag}" >&2
    exit 1
  fi
  if [ "$actual" != "$expected" ]; then
    echo "Error: checksum mismatch for ${asset}" >&2
    echo "  expected: $expected" >&2
    echo "  actual:   $actual" >&2
    exit 1
  fi
  echo "Checksum verified."

  if [ "$os" = "Windows" ]; then
    unzip -q -o "${tmpdir}/${asset}" "${BINARY}" -d "${tmpdir}"
  else
    tar -xzf "${tmpdir}/${asset}" -C "${tmpdir}" "${BINARY}"
  fi

  if [ ! -f "${tmpdir}/${BINARY}" ]; then
    echo "Error: ${BINARY} not found in archive" >&2
    exit 1
  fi

  # Install.
  if [ -w "$INSTALL_DIR" ]; then
    install -m 755 "${tmpdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  else
    echo "Installing to ${INSTALL_DIR} (requires sudo)..."
    sudo install -m 755 "${tmpdir}/${BINARY}" "${INSTALL_DIR}/${BINARY}"
  fi

  echo "Installed pmg ${tag} to ${INSTALL_DIR}/${BINARY}"

  # Verify the install directory is in PATH.
  case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *)
    echo "Warning: ${INSTALL_DIR} is not in your PATH. Add it with:" >&2
    echo "  export PATH=\"${INSTALL_DIR}:\$PATH\"" >&2
    ;;
  esac
}

do_install
