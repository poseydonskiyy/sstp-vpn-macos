#!/bin/bash
set -euo pipefail

project="$(cd "$(dirname "$0")" && pwd)"
build="${1:-$project/build}"
/bin/mkdir -p "$build"
build="$(cd "$build" && pwd)"
cd "$project"

app="$build/SSTP VPN.app"
macos="$app/Contents/MacOS"
resources="$app/Contents/Resources"
parts="$build/objects"
archives="$project/Engine/Vendor"
engine_build="${SSTP_ENGINE_BUILD_DIR:-$build/engine}"
/bin/mkdir -p "$macos" "$resources/Licenses" "$parts" "$engine_build"
engine_build="$(cd "$engine_build" && pwd)"
(cd "$archives" && /usr/bin/shasum -a 256 -c ../sources.sha256)

for chip in arm64 x86_64; do
    "$project/Engine/build-engine.sh" "$archives" "$engine_build" "$chip"
    flags=(-O -swift-version 5 -module-cache-path "$parts/cache" -target "$chip-apple-macos15.0")
    /usr/bin/xcrun swiftc "${flags[@]}" \
        Sources/{Localization,Shared,Certificates,ConnectionTrace,InternetDiagnostics,Helper}.swift -o "$parts/sstp-network-$chip"
    /usr/bin/xcrun clang -target "$chip-apple-macos15.0" -Wno-deprecated-declarations \
        -c Sources/AuthorizationBridge.c -o "$parts/authorization-$chip.o"
    /usr/bin/xcrun swiftc "${flags[@]}" -import-objc-header Sources/AuthorizationBridge.h \
        Sources/{Localization,Shared,Certificates,Storage,WindowsConfig,Session,Model,App}.swift "$parts/authorization-$chip.o" \
        -o "$parts/SSTPVPN-$chip"
done

for name in SSTPVPN sstp-network; do
    /usr/bin/lipo -create "$parts/$name-arm64" "$parts/$name-x86_64" -output "$macos/$name"
done
/usr/bin/lipo -create "$engine_build/sstpc-arm64" "$engine_build/sstpc-x86_64" -output "$macos/sstpc"

/bin/cp Resources/Info.plist "$app/Contents/Info.plist"
/bin/rm -f "$resources/default-ca.pem"
/bin/cp Resources/AppIcon.icns "$resources/"
/bin/cp -R Resources/{en,ru}.lproj "$resources/"
/bin/cp LICENSE "$resources/Licenses/SSTP VPN.txt"
/usr/bin/tar -xOzf "$archives/sstp-client-1.0.20.tar.gz" sstp-client-1.0.20/COPYING > "$resources/Licenses/sstp-client.txt"
/usr/bin/tar -xOzf "$archives/openssl-3.5.9.tar.gz" openssl-3.5.9/LICENSE.txt > "$resources/Licenses/OpenSSL.txt"
/usr/bin/tar -xOzf "$archives/libevent-2.1.13-stable.tar.gz" libevent-2.1.13-stable/LICENSE > "$resources/Licenses/libevent.txt"
/usr/bin/codesign --force --sign "${SSTP_SIGN_IDENTITY:--}" "$macos/sstpc"
/usr/bin/codesign --force --sign "${SSTP_SIGN_IDENTITY:--}" "$macos/sstp-network"
/usr/bin/codesign --force --sign "${SSTP_SIGN_IDENTITY:--}" "$app"
/usr/bin/codesign --verify --deep --strict "$app"
