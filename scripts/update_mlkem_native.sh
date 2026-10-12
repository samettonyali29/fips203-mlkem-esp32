#!/usr/bin/env bash
# Copyright (c) 2026 The fips203-mlkem-esp32 authors
# SPDX-License-Identifier: Apache-2.0
#
# Re-vendor the mlkem-native sources into src/.
#
# usage: bash scripts/update_mlkem_native.sh /path/to/mlkem-native
#
# Copies the portable C implementation (mlkem/src, without the native
# assembly backends) and the public header mlkem_native.h. The ESP32 port's
# own files are NOT touched:
#   src/mlkem_native_config.h   (ESP32 configuration -- compare it with the
#                                new upstream mlkem/mlkem_native_config.h and
#                                merge new options by hand)
#   src/mlkem768_build.c, src/mlkem1024_build.c, src/randombytes.c,
#   src/mlkem_esp32.h, src/MLKEM*.h
#
# Afterwards re-run the conformance tests (examples/mlkem_test_vectors).

set -euo pipefail

UP=${1:?usage: $0 /path/to/mlkem-native}
DST=$(cd "$(dirname "$0")/.." && pwd)/src
[ -f "$UP/mlkem/mlkem_native.h" ] || { echo "not an mlkem-native checkout: $UP" >&2; exit 1; }

cp "$UP"/mlkem/src/*.c "$UP"/mlkem/src/*.h "$UP"/mlkem/src/zetas.inc "$DST"/
cp "$UP"/mlkem/src/fips202/*.c "$UP"/mlkem/src/fips202/*.h "$DST"/fips202/
cp "$UP"/mlkem/src/native/api.h "$UP"/mlkem/src/native/meta.h "$DST"/native/
cp "$UP"/mlkem/src/fips202/native/api.h "$UP"/mlkem/src/fips202/native/auto.h "$DST"/fips202/native/
cp "$UP"/mlkem/mlkem_native.h "$DST"/
cp "$UP"/LICENSE "$DST"/LICENSE.mlkem-native

# The level-dependent sources must still be exactly these three files.
dep=$(grep -L 'MLK_CONFIG_MULTILEVEL_NO_SHARED' "$DST"/*.c | xargs -n1 basename | \
      grep -vE '^(mlkem768_build|mlkem1024_build|randombytes)\.c$' | sort | tr '\n' ' ')
if [ "$dep" != "indcpa.c kem.c poly_k.c " ]; then
  echo "WARNING: level-dependent sources changed to: $dep" >&2
  echo "         update src/mlkem768_build.c and src/mlkem1024_build.c" >&2
fi

echo "Updated $DST from $UP"
echo "Now review: diff -u $UP/mlkem/mlkem_native_config.h $DST/mlkem_native_config.h"
