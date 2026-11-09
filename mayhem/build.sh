#!/usr/bin/env bash
#
# mayhem/build.sh — builds xrdp's protocol libraries with the sanitizers, the four fuzz harnesses
# (plus a standalone reproducer each) and the project's own unit-test programs.
# Runs inside the commit image as `mayhem` in /mayhem. Re-runnable and offline: everything comes from
# apt packages installed in the Dockerfile and the repo itself.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
SAN="$SRC/mayhem/build-san"
TST="$SRC/mayhem/build-test"

# The painter and rfxcodec submodules are empty in the fork and only feed the xrdp server binary;
# the libraries under test (libcommon, libipm, libxrdp) do not need them.
CONFIGURE_ARGS="--disable-painter --disable-rfxcodec --disable-pam --disable-fuse --disable-jpeg
  --disable-pixman --disable-ibus --disable-shared --enable-static"

autoreconf -fi

# 1) Sanitized + SanCov-instrumented libraries (-fsanitize=fuzzer-no-link puts coverage counters in
#    the fuzzed code). `alignment` and `shift-base` are relaxed: the parse.h in_uint*_le macros do
#    unaligned loads and the BER/PER length decoders shift into the sign bit on purpose-built wire
#    parsing; every other UBSan check and ASan stay halting.
UB_RELAX="-fno-sanitize=alignment,shift-base"
LIB_CFLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $UB_RELAX $DEBUG_FLAGS -O1"
rm -rf "$SAN" && mkdir -p "$SAN" && cd "$SAN"
# shellcheck disable=SC2086
"$SRC/configure" CC="$CC" CFLAGS="$LIB_CFLAGS" $CONFIGURE_ARGS >configure.log 2>&1 \
  || { tail -50 configure.log; exit 1; }
for d in common libipm libxrdp; do
  make -j"$MAYHEM_JOBS" -C "$d" >"make-$d.log" 2>&1 || { tail -50 "make-$d.log"; exit 1; }
done

# 2) Harnesses: fuzzer binary + standalone reproducer, both linked with an LSan-off hook.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$SAN/standalone_main.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$SAN/lsan_off.o"
INC="-I$SAN -I$SRC -I$SRC/common -I$SRC/libxrdp -I$SRC/libipm -I$SRC/mayhem -DHAVE_CONFIG_H"
INC="$INC -DFUZZ_INI=\"$SRC/mayhem/xrdp_fuzz.ini\""
LIBS="$SAN/libxrdp/.libs/libxrdp.a $SAN/libipm/.libs/libipm.a $SAN/common/.libs/libcommon.a"
LIBS="$LIBS -lssl -lcrypto -lpthread -lm -ldl"
HFLAGS="$SANITIZER_FLAGS $UB_RELAX $DEBUG_FLAGS -O1"
for h in fuzz_rdp_connect fuzz_rdp_session fuzz_libipm fuzz_dechunker; do
  # shellcheck disable=SC2086
  $CC $HFLAGS $INC "$SRC/mayhem/$h.c" "$SAN/lsan_off.o" $LIB_FUZZING_ENGINE $LIBS -o "$SRC/$h"
  # shellcheck disable=SC2086
  $CC $HFLAGS $INC "$SRC/mayhem/$h.c" "$SAN/standalone_main.o" "$SAN/lsan_off.o" $LIBS \
      -o "$SRC/$h-standalone"
done

# 3) The project's own unit tests, built with the normal flags in an independent tree.
rm -rf "$TST" && mkdir -p "$TST" && cd "$TST"
# shellcheck disable=SC2086
env -u CFLAGS -u LDFLAGS "$SRC/configure" CC="$CC" CFLAGS="-g -O2 $COVERAGE_FLAGS" \
    LDFLAGS="$COVERAGE_FLAGS" --enable-tests $CONFIGURE_ARGS >configure.log 2>&1 \
  || { tail -50 configure.log; exit 1; }
for d in common libipm libxrdp; do
  make -j"$MAYHEM_JOBS" -C "$d" >"make-$d.log" 2>&1 || { tail -50 "make-$d.log"; exit 1; }
done
for d in common libipm libxrdp; do
  make -j"$MAYHEM_JOBS" -C "tests/$d" check TESTS= >"make-tests-$d.log" 2>&1 \
    || { tail -50 "make-tests-$d.log"; exit 1; }
done
