/*
 * ML-KEM FIPS 203 Test Vector Verification (NIST ACVP)
 *
 * Verifies this implementation against official NIST ACVP test vectors for
 * all three parameter sets, to ensure conformance with FIPS 203.
 *
 * Test vector source:
 *   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/
 *   ML-KEM-keyGen-FIPS203, ML-KEM-encapDecap-FIPS203
 * converted into acvp_vectors.h by scripts/gen_acvp_vectors.py
 * (regenerate with --all to include every ACVP test case).
 *
 * What this tests, per parameter set:
 *   1. KeyGen:  (d, z) -> (ek, dk) matches NIST expected output (SHA-256)
 *   2. Encaps:  (ek, m) -> (c, K) matches NIST expected output
 *   3. Decaps:  (dk, c) -> K matches NIST expected output, including
 *               ciphertexts that must be implicitly rejected
 *   4. Encapsulation key check (FIPS 203 Section 7.2, modulus check)
 *   5. Decapsulation key check (FIPS 203 Section 7.3, hash check)
 *   6. Randomized round trips with the hardware RNG
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLKEM.h>
#include <mbedtls/sha256.h>
#include "acvp_vectors.h"

/* Scratch buffers, sized for the largest parameter set (ML-KEM-1024). */
static uint8_t bufA[MLKEM1024::SECRET_KEY_SIZE];
static uint8_t bufB[MLKEM1024::SECRET_KEY_SIZE];
static uint8_t bufC[MLKEM1024::CIPHERTEXT_SIZE];
static uint8_t ss[32], ss2[32], tmp[64];

static int pass = 0;
static int fail = 0;

/* Decode a hex string into out; returns the number of bytes. */
static size_t unhex(const char *hex, uint8_t *out) {
  size_t n = 0;
  auto nib = [](char c) -> uint8_t {
    return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10;
  };
  for (; hex[0] && hex[1]; hex += 2) {
    out[n++] = (nib(hex[0]) << 4) | nib(hex[1]);
  }
  return n;
}

static bool matchesHex(const uint8_t *data, size_t len, const char *hex) {
  uint8_t expect[64];
  return unhex(hex, expect) == len && memcmp(data, expect, len) == 0;
}

static bool sha256Matches(const uint8_t *data, size_t len, const char *hex) {
  uint8_t digest[32];
  mbedtls_sha256(data, len, digest, 0);
  return matchesHex(digest, sizeof(digest), hex);
}

static void report(bool ok, const char *what, unsigned tcId) {
  if (ok) {
    pass++;
  } else {
    fail++;
    Serial.printf("  [FAIL] %s tcId=%u\n", what, tcId);
  }
}

template <class KEM, size_t NKG, size_t NEN, size_t NDE, size_t NEK, size_t NDK>
void runLevel(const acvp_keygen_t (&keygen)[NKG],
              const acvp_encap_t (&encap)[NEN],
              const acvp_decap_t (&decap)[NDE],
              const acvp_keycheck_t (&ekcheck)[NEK],
              const acvp_keycheck_t (&dkcheck)[NDK]) {
  const int passBefore = pass, failBefore = fail;
  unsigned long t0 = millis();
  Serial.printf("\nML-KEM-%u\n", KEM::PARAMETER_SET);

  /* 1. KeyGen: seed = d || z */
  for (const acvp_keygen_t &t : keygen) {
    unhex(t.d, tmp);
    unhex(t.z, tmp + 32);
    int ret = KEM::generateKeypairFromSeed(bufA, bufB, tmp);
    report(ret == 0 && sha256Matches(bufA, KEM::PUBLIC_KEY_SIZE, t.ek_sha256) &&
               sha256Matches(bufB, KEM::SECRET_KEY_SIZE, t.dk_sha256),
           "keyGen", t.tcId);
  }
  Serial.printf("  keyGen:          %u tests\n", (unsigned)NKG);

  /* 2. Encapsulation with fixed randomness m */
  for (const acvp_encap_t &t : encap) {
    unhex(t.ek, bufA);
    unhex(t.m, tmp);
    int ret = KEM::encapsulateFromSeed(bufC, ss, bufA, tmp);
    report(ret == 0 && sha256Matches(bufC, KEM::CIPHERTEXT_SIZE, t.c_sha256) &&
               matchesHex(ss, 32, t.k),
           "encapsulation", t.tcId);
  }
  Serial.printf("  encapsulation:   %u tests\n", (unsigned)NEN);

  /* 3. Decapsulation (valid and implicitly rejected ciphertexts) */
  for (const acvp_decap_t &t : decap) {
    unhex(t.dk, bufB);
    unhex(t.c, bufC);
    int ret = KEM::decapsulate(ss, bufC, bufB);
    report(ret == 0 && matchesHex(ss, 32, t.k), "decapsulation", t.tcId);
  }
  Serial.printf("  decapsulation:   %u tests\n", (unsigned)NDE);

  /* 4./5. Key checks: valid keys must pass, invalid keys must fail */
  for (const acvp_keycheck_t &t : ekcheck) {
    unhex(t.key, bufA);
    report((KEM::checkPublicKey(bufA) == 0) == t.valid, "ekCheck", t.tcId);
  }
  for (const acvp_keycheck_t &t : dkcheck) {
    unhex(t.key, bufB);
    report((KEM::checkSecretKey(bufB) == 0) == t.valid, "dkCheck", t.tcId);
  }
  Serial.printf("  key checks:      %u tests\n", (unsigned)(NEK + NDK));

  /* 6. Randomized round trips + implicit rejection */
  const int ROUNDS = 20;
  for (int i = 0; i < ROUNDS; i++) {
    bool ok = KEM::generateKeypair(bufA, bufB) == 0 &&
              KEM::encapsulate(bufC, ss, bufA) == 0 &&
              KEM::decapsulate(ss2, bufC, bufB) == 0 &&
              memcmp(ss, ss2, 32) == 0;
    report(ok, "round trip", i);
    bufC[(i * 37) % KEM::CIPHERTEXT_SIZE] ^= 1 << (i % 8);
    ok = KEM::decapsulate(ss2, bufC, bufB) == 0 && memcmp(ss, ss2, 32) != 0;
    report(ok, "implicit rejection", i);
  }
  Serial.printf("  random rounds:   %d x (round trip + tamper)\n", ROUNDS);

  Serial.printf("  -> %s: %d passed, %d failed (%lu ms)\n",
                fail == failBefore ? "PASS" : "FAIL", pass - passBefore,
                fail - failBefore, millis() - t0);
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("================================================");
  Serial.println("  ML-KEM FIPS 203 Test Vector Verification");
  Serial.println("  (NIST ACVP ML-KEM-keyGen / encapDecap)");
  Serial.println("================================================");

  runLevel<MLKEM512>(acvp_keygen_512, acvp_encap_512, acvp_decap_512,
                     acvp_ekcheck_512, acvp_dkcheck_512);
  runLevel<MLKEM768>(acvp_keygen_768, acvp_encap_768, acvp_decap_768,
                     acvp_ekcheck_768, acvp_dkcheck_768);
  runLevel<MLKEM1024>(acvp_keygen_1024, acvp_encap_1024, acvp_decap_1024,
                      acvp_ekcheck_1024, acvp_dkcheck_1024);

  memset(bufB, 0, sizeof(bufB));
  Serial.println();
  Serial.println("================================================");
  Serial.printf("  Results: %d passed, %d failed\n", pass, fail);
  Serial.println(fail == 0 ? "  ALL TESTS PASSED -- FIPS 203 conformant"
                           : "  SOME TESTS FAILED");
  Serial.println("================================================");
}

void loop() {
  delay(1000);
}
