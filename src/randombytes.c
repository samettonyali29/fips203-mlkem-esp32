/*
 * randombytes.c - ESP32 hardware RNG for mlkem-native
 *
 * mlkem-native calls mlk_randombytes() (see mlkem_native_config.h) for:
 *   - keypair():  64 bytes (d || z, FIPS 203 Algorithm 19)
 *   - enc():      32 bytes (m, FIPS 203 Algorithm 20)
 *
 * esp_fill_random() reads the ESP32 hardware RNG. Its output is true random
 * whenever an entropy source is running: Wi-Fi or Bluetooth enabled, or
 * bootloader_random_enable() active (see the "Random Number Generation"
 * chapter of the ESP-IDF API reference). With all of them off the RNG
 * output should be treated as pseudo-random only; for key generation in
 * production, enable Wi-Fi/BT first. The function itself cannot fail.
 *
 * The symbol is namespaced (mlkem_esp32_) on purpose: the Arduino-ESP32
 * core links libsodium, which already exports `randombytes`.
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>
#include <esp_random.h>
#include "mlkem_esp32.h"

int mlkem_esp32_randombytes(uint8_t *out, size_t outlen)
{
  if (outlen == 0)
  {
    return 0;
  }
  if (out == NULL)
  {
    return -1;
  }
  esp_fill_random(out, outlen);
  return 0;
}
