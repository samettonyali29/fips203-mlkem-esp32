/*
 * Simple ML-KEM-768 key exchange using the MLKEM768 C++ wrapper.
 *
 * Alice generates a keypair and publishes the public key. Bob encapsulates
 * a fresh shared secret to it and sends the ciphertext back. Alice
 * decapsulates the ciphertext and obtains the same 32-byte secret, which
 * both can now use as a symmetric key (e.g. AES-256-GCM).
 *
 * The library keeps its large temporaries on the heap (< 2 KB stack), so it
 * can be used straight from setup()/loop(). The key buffers are static here
 * to keep them off the 8 KB loop() stack as well.
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLKEM768.h>

static uint8_t pk[MLKEM768::PUBLIC_KEY_SIZE];   // Alice's public key
static uint8_t sk[MLKEM768::SECRET_KEY_SIZE];   // Alice's secret key
static uint8_t ct[MLKEM768::CIPHERTEXT_SIZE];   // Bob -> Alice
static uint8_t ssBob[MLKEM768::SHARED_SECRET_SIZE];
static uint8_t ssAlice[MLKEM768::SHARED_SECRET_SIZE];

static void printHex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s: ", label);
  for (size_t i = 0; i < len; i++) Serial.printf("%02X", data[i]);
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Alice: generate keypair
  if (MLKEM768::generateKeypair(pk, sk) != 0) {
    Serial.println("Keygen failed!");
    return;
  }
  Serial.println("Keypair generated.");

  // Bob: encapsulate a shared secret to Alice's public key
  if (MLKEM768::encapsulate(ct, ssBob, pk) != 0) {
    Serial.println("Encapsulation failed!");
    return;
  }
  Serial.printf("Encapsulated (ciphertext: %u bytes)\n", (unsigned)sizeof(ct));

  // Alice: decapsulate the ciphertext
  if (MLKEM768::decapsulate(ssAlice, ct, sk) != 0) {
    Serial.println("Decapsulation failed!");
    return;
  }

  printHex("Bob's secret  ", ssBob, sizeof(ssBob));
  printHex("Alice's secret", ssAlice, sizeof(ssAlice));
  if (memcmp(ssBob, ssAlice, sizeof(ssBob)) == 0) {
    Serial.println("Shared secrets match!");
  } else {
    Serial.println("Shared secrets DIFFER!");
  }

  // Clean up secrets
  memset(sk, 0, sizeof(sk));
  memset(ssBob, 0, sizeof(ssBob));
  memset(ssAlice, 0, sizeof(ssAlice));
}

void loop() {
  delay(1000);
}
