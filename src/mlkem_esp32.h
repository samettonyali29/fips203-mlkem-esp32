/*
 * mlkem_esp32.h - C API of all three ML-KEM parameter sets
 *
 * mlkem_native.h declares the API of a single parameter set (the one given
 * by MLK_CONFIG_PARAMETER_SET, 512 by default). This header includes it once
 * per parameter set, so that the complete API is visible:
 *
 *   PQCP_MLKEM_NATIVE_MLKEM512_keypair / _keypair_derand
 *   PQCP_MLKEM_NATIVE_MLKEM512_enc     / _enc_derand
 *   PQCP_MLKEM_NATIVE_MLKEM512_dec
 *   PQCP_MLKEM_NATIVE_MLKEM512_check_pk / _check_sk
 *   ... and the same for MLKEM768 and MLKEM1024.
 *
 * Size constants: MLKEM{512,768,1024}_{PUBLICKEYBYTES,SECRETKEYBYTES,
 * CIPHERTEXTBYTES}, MLKEM_BYTES (shared secret), MLKEM_SYMBYTES.
 * Error codes:    MLK_ERR_FAIL, MLK_ERR_RNG_FAIL, MLK_ERR_INVALID_PK, ...
 *
 * All functions return 0 on success and a negative MLK_ERR_* code on error.
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLKEM_ESP32_H
#define MLKEM_ESP32_H

#if defined(MLK_CONFIG_PARAMETER_SET)
#define MLKEM_ESP32_RESTORE_PARAMETER_SET
#pragma push_macro("MLK_CONFIG_PARAMETER_SET")
#undef MLK_CONFIG_PARAMETER_SET
#endif

/* API for ML-KEM-512 */
#undef MLK_H
#define MLK_CONFIG_PARAMETER_SET 512
#include "mlkem_native.h"
#undef MLK_CONFIG_PARAMETER_SET

/* API for ML-KEM-768 */
#undef MLK_H
#define MLK_CONFIG_PARAMETER_SET 768
#include "mlkem_native.h"
#undef MLK_CONFIG_PARAMETER_SET

/* API for ML-KEM-1024 */
#undef MLK_H
#define MLK_CONFIG_PARAMETER_SET 1024
#include "mlkem_native.h"
#undef MLK_CONFIG_PARAMETER_SET

/* MLK_H stays defined: every declaration is present now, so a later
 * #include "mlkem_native.h" is a harmless no-op. */
#if defined(MLKEM_ESP32_RESTORE_PARAMETER_SET)
#pragma pop_macro("MLK_CONFIG_PARAMETER_SET")
#undef MLKEM_ESP32_RESTORE_PARAMETER_SET
#else
#define MLK_CONFIG_PARAMETER_SET 512 /* library default, see config */
#endif

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The random source used by keypair() and enc(): the ESP32 hardware RNG
 * (esp_fill_random). Fills out with outlen bytes, returns 0 on success.
 * Output is true random only while Wi-Fi/BT (or bootloader_random_enable())
 * is active -- see randombytes.c.
 */
int mlkem_esp32_randombytes(uint8_t *out, size_t outlen);

#ifdef __cplusplus
}
#endif

#endif /* !MLKEM_ESP32_H */
