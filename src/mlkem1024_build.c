/*
 * mlkem1024_build.c - ML-KEM-1024 level-specific compilation unit
 *
 * Arduino compiles every .c file in src/ once. Those direct compiles form
 * the ML-KEM-512 build and also contain all level-independent code
 * (FIPS 202, NTT, compression, sampling, ...), see mlkem_native_config.h.
 *
 * This file compiles the level-dependent part of mlkem-native a second time
 * for ML-KEM-1024 (K=4, ETA1=2, DU=11, DV=5; PK=1568, SK=3168, CT=1568 bytes):
 *
 *   - MLK_CONFIG_PARAMETER_SET=1024 selects the parameter set.
 *   - MLK_CONFIG_MULTILEVEL_NO_SHARED omits the shared code (it is already
 *     part of the ML-KEM-512 build) and makes MLK_ADD_PARAM_SET() suffix
 *     all level-dependent symbols with "1024", so they cannot clash with the
 *     ML-KEM-512 symbols. The public API becomes
 *     PQCP_MLKEM_NATIVE_MLKEM1024_{keypair,keypair_derand,enc,enc_derand,
 *     dec,check_pk,check_sk}.
 *
 * Only indcpa.c, kem.c and poly_k.c depend on the parameter set; all other
 * sources compile to empty units under MLK_CONFIG_MULTILEVEL_NO_SHARED.
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define MLK_CONFIG_PARAMETER_SET 1024
#define MLK_CONFIG_MULTILEVEL_NO_SHARED

#include "indcpa.c"
#include "kem.c"
#include "poly_k.c"
