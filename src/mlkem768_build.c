/*
 * mlkem768_build.c - ML-KEM-768 level-specific compilation unit
 *
 * Arduino compiles every .c file in src/ once. Those direct compiles form
 * the ML-KEM-512 build and also contain all level-independent code
 * (FIPS 202, NTT, compression, sampling, ...), see mlkem_native_config.h.
 *
 * This file compiles the level-dependent part of mlkem-native a second time
 * for ML-KEM-768 (K=3, ETA1=2, DU=10, DV=4; PK=1184, SK=2400, CT=1088 bytes):
 *
 *   - MLK_CONFIG_PARAMETER_SET=768 selects the parameter set.
 *   - MLK_CONFIG_MULTILEVEL_NO_SHARED omits the shared code (it is already
 *     part of the ML-KEM-512 build) and makes MLK_ADD_PARAM_SET() suffix
 *     all level-dependent symbols with "768", so they cannot clash with the
 *     ML-KEM-512 symbols. The public API becomes
 *     PQCP_MLKEM_NATIVE_MLKEM768_{keypair,keypair_derand,enc,enc_derand,
 *     dec,check_pk,check_sk}.
 *
 * Only indcpa.c, kem.c and poly_k.c depend on the parameter set; all other
 * sources compile to empty units under MLK_CONFIG_MULTILEVEL_NO_SHARED.
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#define MLK_CONFIG_PARAMETER_SET 768
#define MLK_CONFIG_MULTILEVEL_NO_SHARED

#include "indcpa.c"
#include "kem.c"
#include "poly_k.c"
