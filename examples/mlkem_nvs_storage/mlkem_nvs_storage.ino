/*
 * ML-KEM-768 NVS Persistent Key Storage Example
 *
 * Demonstrates storing an ML-KEM-768 keypair in the ESP32's Non-Volatile
 * Storage (NVS) so that the device keeps a stable identity across reboots.
 *
 * First boot:  Generates a new keypair and stores it in NVS flash.
 * Next boots:  Loads the existing keypair from NVS.
 *
 * With STORE_SEED_ONLY = true only the 64-byte FIPS 203 seed (d || z) is
 * stored and the keypair is re-derived on every boot (a few milliseconds);
 * with false the full 1184 + 2400 byte keypair is stored.
 *
 * The example then runs a key exchange against the loaded key to prove it
 * works. Send 'e' over the serial monitor to erase the key and reboot.
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLKEM768.h>
#include <MLKEM_NVS.h>

static const char *NVS_NAMESPACE = "mlkem";
static const bool STORE_SEED_ONLY = true;

static uint8_t pk[MLKEM768::PUBLIC_KEY_SIZE];
static uint8_t sk[MLKEM768::SECRET_KEY_SIZE];
static uint8_t ct[MLKEM768::CIPHERTEXT_SIZE];
static uint8_t ssSender[MLKEM768::SHARED_SECRET_SIZE];
static uint8_t ssReceiver[MLKEM768::SHARED_SECRET_SIZE];

static void printHex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s (%u bytes): ", label, (unsigned)len);
  for (size_t i = 0; i < len && i < 16; i++) Serial.printf("%02X", data[i]);
  if (len > 16) Serial.print("...");
  Serial.println();
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  Serial.println();
  Serial.println("=== ML-KEM-768 NVS Key Storage Demo ===");
  Serial.println();

  // Check if we already have a stored keypair
  if (MLKEM768_NVS::hasKeypair(NVS_NAMESPACE)) {
    Serial.println("Found existing keypair in NVS, loading...");
    unsigned long start = micros();
    if (!MLKEM768_NVS::loadKeypair(NVS_NAMESPACE, pk, sk)) {
      Serial.println("ERROR: Failed to load keypair (missing or corrupted)!");
      return;
    }
    Serial.printf("Keypair loaded from NVS in %.2f ms\n", (micros() - start) / 1000.0);
  } else {
    Serial.printf("No keypair in NVS. Generating a new one (%s)...\n",
                  STORE_SEED_ONLY ? "storing 64-byte seed"
                                  : "storing full keypair");
    unsigned long start = micros();
    int ret = MLKEM768_NVS::generateAndSave(NVS_NAMESPACE, pk, sk, STORE_SEED_ONLY);
    if (ret != 0) {
      Serial.printf("ERROR: generateAndSave failed (code %d)\n", ret);
      return;
    }
    Serial.printf("Keypair generated and saved to NVS in %.2f ms\n",
                  (micros() - start) / 1000.0);
  }

  // The public key is the device's stable identity; it survives reboots.
  printHex("Public Key", pk, sizeof(pk));

  // A peer encapsulates to our stored public key...
  if (MLKEM768::encapsulate(ct, ssSender, pk) != 0) {
    Serial.println("ERROR: Encapsulation failed!");
    return;
  }
  // ...and we decapsulate with the stored secret key.
  if (MLKEM768::decapsulate(ssReceiver, ct, sk) != 0) {
    Serial.println("ERROR: Decapsulation failed!");
    return;
  }
  if (memcmp(ssSender, ssReceiver, sizeof(ssSender)) == 0) {
    Serial.println("Key exchange OK -- stored keys work correctly!");
  } else {
    Serial.println("ERROR: Shared secrets differ!");
  }

  memset(sk, 0, sizeof(sk));
  memset(ssSender, 0, sizeof(ssSender));
  memset(ssReceiver, 0, sizeof(ssReceiver));

  Serial.println("\nReboot the board: the same public key will be loaded.");
  Serial.println("Send 'e' to erase the stored keypair and reboot.");
}

void loop() {
  if (Serial.available() && Serial.read() == 'e') {
    MLKEM768_NVS::eraseKeypair(NVS_NAMESPACE);
    Serial.println("Keypair erased. Rebooting...");
    delay(100);
    ESP.restart();
  }
  delay(50);
}
