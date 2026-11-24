#!/bin/bash
set -euo pipefail

engine="$(cd "$(dirname "$0")" && pwd)"
archives="$1"
build="$2"
chip="$3"
prefix="$build/lib-$chip"
source="$build/src-$chip/sstp-client-1.0.20"

"$engine/build-libraries.sh" "$archives" "$build" "$chip"
mkdir -p "$source"
cd "$source"
/usr/bin/tar -xzf "$archives/sstp-client-1.0.20.tar.gz" --strip-components 1
/usr/bin/patch -p1 < "$engine/macos.patch"
cp "$engine/sstp-macos-trust.h" src/

export MACOSX_DEPLOYMENT_TARGET=15.0
export SDKROOT="$(/usr/bin/xcrun --sdk macosx --show-sdk-path)"
export CC="$(/usr/bin/xcrun -f clang)"
export CFLAGS="-O2 -arch $chip"
export LDFLAGS="-arch $chip -framework Security -framework CoreFoundation"
export LIBEVENT_CFLAGS="-I$prefix/include"
export LIBEVENT_LIBS="-L$prefix/lib -levent"

./configure --disable-shared --enable-static --disable-ppp-plugin \
    --with-openssl="$prefix" --with-runtime-dir=/private/var/run/sstpgui \
    --enable-user=nobody --enable-group=nobody
/usr/bin/make -j "${SSTP_BUILD_JOBS:-5}"
cp src/sstpc "$build/sstpc-$chip"
