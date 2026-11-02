#!/bin/bash

# Check if vhs is installed
if ! command -v vhs &> /dev/null; then
    echo "vhs could not be found"
    exit 1
fi

# Switch to the script directory
cd "$(dirname "$0")"

# Enumerate all .tape files in the current directory
for file in *.tape; do
    vhs "$file"
done