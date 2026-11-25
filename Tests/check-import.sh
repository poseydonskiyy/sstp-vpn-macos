#!/bin/bash
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
/usr/bin/xcrun swiftc -module-cache-path "$tmp/cache" \
    "$project"/Sources/{Shared,WindowsConfig,ConnectionTrace}.swift "$project/Tests/WindowsImport.swift" -o "$tmp/check"
"$tmp/check"
