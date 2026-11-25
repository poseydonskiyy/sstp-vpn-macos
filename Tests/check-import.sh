#!/bin/bash
set -euo pipefail
project="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf -- "$tmp"' EXIT
bundle="$tmp/ImportCheck.app/Contents"
mkdir -p "$bundle/MacOS" "$bundle/Resources"
cp "$project/Resources/Info.plist" "$bundle/Info.plist"
cp -R "$project/Resources/"{en,ru}.lproj "$bundle/Resources/"
check="$bundle/MacOS/SSTPVPN"
/usr/bin/xcrun swiftc -module-cache-path "$tmp/cache" \
    "$project"/Sources/{Localization,Shared,WindowsConfig,ConnectionTrace}.swift "$project/Tests/WindowsImport.swift" -o "$check"
"$check" -AppleLanguages '(ru)'
"$check" -AppleLanguages '(en)' --check-english
cp "$check" "$bundle/MacOS/sstp-network"
"$bundle/MacOS/sstp-network" -AppleLanguages '(ru)' --check-helper
