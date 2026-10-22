#!/bin/sh
# Downloads the PMG release, checks it against checksums.txt and puts it on
# PATH. Reads INPUT_VERSION and INPUT_CACHE. Writes the version and bin-dir
# outputs.
set -eu

repo="safedep/pmg"
nl='
'
cr=$(printf '\r')

# Minimal images such as Alpine have busybox wget but no curl.
if command -v curl >/dev/null 2>&1; then
  downloader=curl
elif command -v wget >/dev/null 2>&1; then
  downloader=wget
else
  printf '%s\n' "::error::PMG needs curl or wget to download the release." >&2
  exit 1
fi
printf '%s\n' "Downloading with ${downloader}"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# checksums.txt and the tarball come over the same connection, so TLS
# is what keeps a host on the path from replacing both. Upstream
# busybox wget, as in the busybox image, does not verify the
# certificate. It prints this note and goes on. Alpine busybox and
# GNU wget verify it and never print the note. wget writes its
# stderr, with the -S headers, to wget.err.
fetch_wget() {
  rc=0
  wget "$@" 2>"${tmpdir}/wget.err" || rc=$?
  if grep -q 'certificate validation not implemented' "${tmpdir}/wget.err"; then
    printf '%s\n' "::error::This wget does not verify TLS certificates, so the action cannot trust the download. Add curl or GNU wget to the image, or use an Alpine image." >&2
    exit 1
  fi
  return "$rc"
}

# GNU wget -q prints nothing on a failure, so this line names the URL
# and the exit code. wget uses 4 for a network error, 5 for TLS and 8
# for an HTTP error.
download() {
  if [ "$downloader" = curl ]; then
    curl -fsSL -o "$2" "$1" && return 0
  else
    fetch_wget -q -O "$2" "$1" && return 0
  fi
  rc=$?
  if [ "$downloader" = wget ]; then
    cat "${tmpdir}/wget.err" >&2
  fi
  printf '%s\n' "::error::Could not download $1 with ${downloader} (exit ${rc})." >&2
  exit 1
}

# Resolve version tag. GitHub redirects /releases/latest to the page
# of the latest tag.
if [ "$INPUT_VERSION" = "latest" ] || [ -z "$INPUT_VERSION" ]; then
  printf '%s\n' "Resolving latest PMG release..."
  latest_url="https://github.com/${repo}/releases/latest"
  if [ "$downloader" = curl ]; then
    location=$(curl -fsSI -o /dev/null -w '%{redirect_url}' "$latest_url")
  else
    fetch_wget -q --spider -S "$latest_url" || true
    location=$(sed -n 's/^ *[Ll]ocation: *\([^ ]*\).*/\1/p' "${tmpdir}/wget.err" | head -n 1)
  fi
  tag=$(printf '%s' "$location" | sed 's|.*/||' | tr -d '\r\n')
  if [ -z "$tag" ]; then
    printf '%s\n' "::error::Could not resolve latest PMG release tag." >&2
    exit 1
  fi
else
  tag="$INPUT_VERSION"
fi
# The tag ends up in paths written to GITHUB_PATH and GITHUB_OUTPUT.
# grep matches each line, so a line break is rejected first.
case "$tag" in
  *"$nl"*|*"$cr"*) tag_ok=false ;;
  *)
    if printf '%s\n' "$tag" | grep -Eqx 'v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?'; then
      tag_ok=true
    else
      tag_ok=false
    fi
    ;;
esac
if [ "$tag_ok" != true ]; then
  shown=$(printf '%s' "$tag" | tr -d '\r\n')
  printf '%s\n' "::error::Invalid PMG version '${shown}'. Use a release tag such as v0.42.0 or v0.42.0-edge.1, or latest." >&2
  exit 1
fi
printf '%s\n' "PMG version: $tag"

# Map architecture.
case "$(uname -m)" in
  x86_64|amd64) arch="x86_64" ;;
  aarch64|arm64) arch="arm64" ;;
  *)
    printf '%s\n' "::error::Unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

asset="pmg_Linux_${arch}.tar.gz"
cache_dir="${RUNNER_TOOL_CACHE:-/opt/hostedtoolcache}/pmg/${tag}/${arch}"
install_dir="$cache_dir"

if [ "$INPUT_CACHE" != "true" ]; then
  install_dir="${RUNNER_TEMP:-/tmp}/pmg-${tag}-${arch}"
fi

mkdir -p "$install_dir"
bin_path="${install_dir}/pmg"
tar_path="${install_dir}/${asset}"

# Always fetch upstream checksums.txt — even on a cache hit — so a
# tampered cache entry is caught before we run the binary.
download "https://github.com/${repo}/releases/download/${tag}/checksums.txt" "${tmpdir}/checksums.txt"
expected=$(grep "  ${asset}\$" "${tmpdir}/checksums.txt" | cut -d' ' -f1 || true)
if [ -z "$expected" ]; then
  printf '%s\n' "::error::No checksum entry for ${asset} in ${tag}/checksums.txt" >&2
  exit 1
fi

need_download=true
if [ "$INPUT_CACHE" = "true" ] && [ -f "$tar_path" ] && [ -x "$bin_path" ]; then
  cached=$(sha256sum "$tar_path" | cut -d' ' -f1)
  if [ "$cached" = "$expected" ]; then
    printf '%s\n' "Cached PMG ${tag} verified against upstream checksum"
    need_download=false
  else
    printf '%s\n' "Cached PMG ${tag} checksum drift (want ${expected}, got ${cached}); refreshing"
    rm -f "$tar_path" "$bin_path"
  fi
fi

if [ "$need_download" = "true" ]; then
  download "https://github.com/${repo}/releases/download/${tag}/${asset}" "$tar_path"
  actual=$(sha256sum "$tar_path" | cut -d' ' -f1)
  if [ "$actual" != "$expected" ]; then
    printf '%s\n' "::error::Checksum mismatch for ${asset}: want ${expected}, got ${actual}" >&2
    exit 1
  fi
  printf '%s\n' "Checksum verified for ${asset}"
  tar -xzf "$tar_path" -C "$install_dir" pmg
  chmod +x "$bin_path"
fi

printf '%s\n' "$install_dir" >> "$GITHUB_PATH"
printf '%s\n' "bin-dir=$install_dir" >> "$GITHUB_OUTPUT"
printf '%s\n' "version=$tag" >> "$GITHUB_OUTPUT"
