#!/bin/bash
set -euo pipefail

archives="$1"
build="$2"
chip="$3"
jobs="${SSTP_BUILD_JOBS:-5}"
prefix="$build/lib-$chip"
mkdir -p "$prefix" "$build/src-$chip"
cd "$build/src-$chip"
export MACOSX_DEPLOYMENT_TARGET=15.0
export CC="$(/usr/bin/xcrun -f clang)"
export SDKROOT="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"

if [[ ! -f "$prefix/lib/libssl.a" || ! -f "$prefix/lib/libcrypto.a" || ! -f "$prefix/include/openssl/ssl.h" ]]; then
    staging="$(mktemp -d "$build/openssl-install-$chip.XXXXXXXX")"
    trap 'rm -rf -- "$staging"' EXIT
    /usr/bin/tar -xzf "$archives/openssl-3.5.9.tar.gz"
    (
        cd openssl-3.5.9
        case "$chip" in
            arm64) target=darwin64-arm64-cc ;;
            x86_64) target=darwin64-x86_64-cc ;;
            *) exit 2 ;;
        esac
        # Install via DESTDIR so the build directory is absent from the linked binaries.
        /usr/bin/perl Configure "$target" no-shared no-module no-tests no-docs \
            --prefix=/usr/local --openssldir=/private/etc/ssl --libdir=lib
        /usr/bin/make -j "$jobs" build_libs
        /usr/bin/make DESTDIR="$staging" install_dev
    )
    /bin/cp -R "$staging/usr/local/include" "$staging/usr/local/lib" "$prefix/"
fi

if [[ ! -f "$prefix/lib/libevent.a" || ! -f "$prefix/include/event2/event.h" ]]; then
    /usr/bin/tar -xzf "$archives/libevent-2.1.13-stable.tar.gz"
    (
        cd libevent-2.1.13-stable
        CFLAGS="-O2 -arch $chip" LDFLAGS="-arch $chip" ./configure \
            --prefix="$prefix" --disable-shared --disable-openssl \
            --disable-samples --disable-libevent-regress --disable-debug-mode
        /usr/bin/make -j "$jobs"
        /usr/bin/make install
    )
fi
