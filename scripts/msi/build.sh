#!/usr/bin/env bash
# build.sh - build the Windows installer with wixl (msitools).
#
# goreleaser runs this as a post-build hook for every target and passes the
# target OS first. The script does nothing for a non-Windows target.
#
# Usage: build.sh <goos> <pmg.exe> <version> <output.msi>
#
# <version> is the release version without the v, for example 1.4.2 or
# 1.4.2-edge.3. MSI ProductVersion takes numbers only, so the prerelease part
# names the channel in the product name instead. The stable and edge builds
# of one version then share a ProductVersion, and AllowSameVersionUpgrades in
# pmg.wxs lets each replace the other.
set -euo pipefail

goos=$1
pmg_exe=$2
version=$3
output=$4

if [[ "$goos" != windows ]]; then
  exit 0
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
