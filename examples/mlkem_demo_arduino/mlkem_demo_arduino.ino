/*
 * ML-KEM-768 Demo for ESP32
 *
 * Demonstrates post-quantum key encapsulation with ML-KEM-768 (FIPS 203)
 * using the plain C API of mlkem-native, and shows the security properties
 * of the scheme:
 *
 *   1. Key generation, encapsulation, decapsulation with timing
 *   2. Tampered ciphertext -> implicit rejection (different, pseudo-random
 *      shared secret; no error is signalled, by design)
 *   3. Malformed public key -> rejected by the FIPS 203 modulus check
 *   4. Corrupted secret key -> rejected by the FIPS 203 hash check
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <mlkem_esp32.h>

static uint8_t pk[MLKEM768_PUBLICKEYBYTES];
static uint8_t sk[MLKEM768_SECRETKEYBYTES];
static uint8_t ct[MLKEM768_CIPHERTEXTBYTES];
static uint8_t ssEnc[MLKEM_BYTES];
static uint8_t ssDec[MLKEM_BYTES];

static void printHex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s (%u bytes): ", label, (unsigned)len);
  for (size_t i = 0; i < len && i < 32; i++) {
    Serial.printf("%02X", data[i]);
  }
  if (len > 32) {
    Serial.print("... [truncated]");
  }
  Serial.println();
}

static void printMemInfo(const char *phase) {
  Serial.printf("[%s] Free heap: %u bytes, largest block: %u bytes, "
                "free stack: %u bytes\n",
                phase, (unsigned)ESP.getFreeHeap(),
                (unsigned)ESP.getMaxAllocHeap(),
                (unsigned)uxTaskGetStackHighWaterMark(NULL));
}

static const char *errName(int ret) {
  switch (ret) {
    case 0: return "OK";
    case MLK_ERR_FAIL: return "MLK_ERR_FAIL";
    case MLK_ERR_OUT_OF_MEMORY: return "MLK_ERR_OUT_OF_MEMORY";
    case MLK_ERR_RNG_FAIL: return "MLK_ERR_RNG_FAIL";
    case MLK_ERR_INVALID_PK: return "MLK_ERR_INVALID_PK";
    case MLK_ERR_INVALID_SK: return "MLK_ERR_INVALID_SK";
    case MLK_ERR_PCT_FAIL: return "MLK_ERR_PCT_FAIL";
    default: return "unknown";
  }
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("========================================");
  Serial.println("  ML-KEM-768 (FIPS 203) Demo for ESP32");
  Serial.println("========================================");
  Serial.println();
  Serial.printf("Sizes: PK=%u bytes, SK=%u bytes, CT=%u bytes, SS=%u bytes\n",
                (unsigned)MLKEM768_PUBLICKEYBYTES,
                (unsigned)MLKEM768_SECRETKEYBYTES,
                (unsigned)MLKEM768_CIPHERTEXTBYTES, (unsigned)MLKEM_BYTES);
  printMemInfo("Start");

  int ret;
  unsigned long start, elapsed;

  // --- 1. Key Generation ---
  Serial.println("\n--- Key Generation ---");
  start = micros();
  ret = PQCP_MLKEM_NATIVE_MLKEM768_keypair(pk, sk);
  elapsed = micros() - start;
  if (ret != 0) {
    Serial.printf("ERROR: keypair failed: %s (%d)\n", errName(ret), ret);
    return;
  }
  Serial.printf("Keypair generated in %.3f ms\n", elapsed / 1000.0);
  printHex("Public Key", pk, sizeof(pk));

  // --- 2. Encapsulation ---
  Serial.println("\n--- Encapsulation ---");
  start = micros();
  ret = PQCP_MLKEM_NATIVE_MLKEM768_enc(ct, ssEnc, pk);
  elapsed = micros() - start;
  if (ret != 0) {
    Serial.printf("ERROR: enc failed: %s (%d)\n", errName(ret), ret);
    return;
  }
  Serial.printf("Encapsulated in %.3f ms\n", elapsed / 1000.0);
  printHex("Ciphertext", ct, sizeof(ct));
  printHex("Shared secret (sender)", ssEnc, sizeof(ssEnc));

  // --- 3. Decapsulation ---
  Serial.println("\n--- Decapsulation ---");
  start = micros();
  ret = PQCP_MLKEM_NATIVE_MLKEM768_dec(ssDec, ct, sk);
  elapsed = micros() - start;
  if (ret != 0) {
    Serial.printf("ERROR: dec failed: %s (%d)\n", errName(ret), ret);
    return;
  }
  Serial.printf("Decapsulated in %.3f ms\n", elapsed / 1000.0);
  printHex("Shared secret (receiver)", ssDec, sizeof(ssDec));
  if (memcmp(ssEnc, ssDec, MLKEM_BYTES) == 0) {
    Serial.println("Key exchange SUCCESS: shared secrets match");
  } else {
    Serial.println("Key exchange FAILED: shared secrets differ");
  }
  printMemInfo("After exchange");

  // --- 4. Tampered ciphertext: implicit rejection ---
  Serial.println("\n--- Tamper Test (ciphertext) ---");
  ct[0] ^= 0x01;  // flip one bit
  ret = PQCP_MLKEM_NATIVE_MLKEM768_dec(ssDec, ct, sk);
  ct[0] ^= 0x01;
  if (ret == 0 && memcmp(ssEnc, ssDec, MLKEM_BYTES) != 0) {
    Serial.println("Tampered ciphertext correctly REJECTED (implicit rejection:");
    Serial.println("  decapsulation returns an unrelated pseudo-random secret)");
    printHex("  Secret from tampered ct", ssDec, sizeof(ssDec));
  } else {
    Serial.printf("WARNING: unexpected result (ret=%d)\n", ret);
  }

  // --- 5. Malformed public key: modulus check ---
  Serial.println("\n--- Malformed Public Key Test ---");
  uint8_t saved[2] = {pk[0], pk[1]};
  pk[0] = 0xFF;  // first 12-bit coefficient := 0xFFF = 4095 >= q = 3329
  pk[1] |= 0x0F;
  ret = PQCP_MLKEM_NATIVE_MLKEM768_check_pk(pk);
  Serial.printf("check_pk: %s\n", errName(ret));
  ret = PQCP_MLKEM_NATIVE_MLKEM768_enc(ct, ssEnc, pk);
  Serial.printf("enc with malformed key: %s -> %s\n", errName(ret),
                ret == MLK_ERR_INVALID_PK ? "correctly REJECTED" : "WARNING");
  pk[0] = saved[0];
  pk[1] = saved[1];

  // --- 6. Corrupted secret key: hash check ---
  Serial.println("\n--- Corrupted Secret Key Test ---");
  const size_t pkOffset = 384 * 3;  // sk = s || pk || H(pk) || z
  sk[pkOffset] ^= 0x01;
  ret = PQCP_MLKEM_NATIVE_MLKEM768_dec(ssDec, ct, sk);
  Serial.printf("dec with corrupted key: %s -> %s\n", errName(ret),
                ret == MLK_ERR_INVALID_SK ? "correctly REJECTED" : "WARNING");
  sk[pkOffset] ^= 0x01;

  // Zeroize sensitive material
  memset(sk, 0, sizeof(sk));
  memset(ssEnc, 0, sizeof(ssEnc));
  memset(ssDec, 0, sizeof(ssDec));

  Serial.println("\n========================================");
  printMemInfo("End");
  Serial.println("Demo complete.");
  Serial.println("========================================");
}

void loop() {
  delay(1000);
}
