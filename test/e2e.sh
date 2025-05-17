#!/bin/bash

set -e

scriptDir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
pmg=$scriptDir/../bin/pmg

echo "Running e2e tests..."

## All these should be successful
$pmg npm install express --dry-run
$pmg --dry-run npm install express
$pmg --dry-run pnpm add express

## All these should fail
$pmg --dry-run npm install nyc-config@10.0.0