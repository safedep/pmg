#!/usr/bin/env bash
# build.sh - build the Windows installer with wixl (msitools).
#
# goreleaser runs this as a post-build hook for every target and passes the
# target OS first. The script does nothing for a non-Windows target.
#
# Usage: build.sh <goos> <goarch> <pmg.exe> <version> <output.msi>
#
# <version> is the release version without the v, for example 1.4.2 or
# 1.4.2-edge.3. MSI ProductVersion takes numbers only, so the prerelease part
# names the channel in the product name instead. The stable and edge builds
# of one version then share a ProductVersion, and AllowSameVersionUpgrades in
# pmg.wxs lets each replace the other.
set -euo pipefail

goos=$1
goarch=$2
pmg_exe=$3
version=$4
output=$5

if [[ "$goos" != windows ]]; then
  exit 0
fi

# The MSI is an x64 package with one fixed output name. A second Windows
# architecture needs its own package, not a silent overwrite of this one.
if [[ "$goarch" != amd64 ]]; then
  echo "Error: the MSI is built for windows/amd64 only, got windows/$goarch" >&2
  exit 1
fi

if ! command -v wixl > /dev/null; then
  echo "Error: wixl is not installed. It builds the Windows installer. Install msitools: apt-get install wixl, or brew install msitools" >&2
  exit 1
fi

base=${version%%-*}
prerelease=${version#"$base"}
prerelease=${prerelease#-}
if [[ ! "$base" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version $version does not start with major.minor.patch" >&2
  exit 1
fi

product_name=pmg
if [[ -n "$prerelease" ]]; then
  product_name="pmg (${prerelease%%.*})"
fi

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$(dirname "$output")"
wixl --arch x64 \
  --define "Version=$base" \
  --define "ProductName=$product_name" \
  --define "PmgExe=$pmg_exe" \
  --output "$output" \
  "$script_dir/pmg.wxs"
echo "built $output: $product_name $base"
