#!/bin/bash

set -e

scriptDir=$(dirname "$0")
pmg=$scriptDir/../bin/pmg

echo "Running e2e tests..."

## All these should be successful
$pmg --debug --dry-run npm install express
$pmg --debug --dry-run npm install express
$pmg --debug --dry-run pnpm add express

## All these should fail
$pmg --debug --dry-run npm install nyc-config@10.0.0 || exit 1