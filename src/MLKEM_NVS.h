/*
 * MLKEM_NVS.h - NVS (Non-Volatile Storage) helper for ML-KEM keypairs
 *
 * Persists ML-KEM keypairs in the ESP32 NVS flash partition so they survive
 * reboots and power cycles. Works with every parameter set:
 *
 *   MLKEM_NVS<MLKEM768>::generateAndSave("mlkem", pk, sk);
 *   MLKEM_NVS<MLKEM768>::loadKeypair("mlkem", pk, sk);
 *
 * Two storage formats are supported:
 *
 *   1. Full keypair ("pk" + "sk" entries, 2-4.7 KB of flash).
 *      Loading is instant.
 *   2. Seed only ("seed" entry, 64 bytes, FIPS 203 d || z).
 *      The keypair is re-derived on load (tens of milliseconds). This is
 *      the most compact form, and a seed cannot be partially corrupted into
 *      a different-but-valid key. Combine with NVS encryption for secrecy.
 *
 * Loaded secret keys are validated with the FIPS 203 hash check, so a
 * corrupted flash entry is reported as a load failure.
 *
 * The parameter set is stored alongside the key ("lvl"), so a key that was
 * saved as ML-KEM-512 is never loaded as ML-KEM-768.
 *
 * NVS stores data unencrypted unless flash/NVS encryption is enabled on
 * the chip. Treat NVS contents as readable by anyone with physical access.
 *
 * Requires: ESP32 Arduino core (Preferences library, included by default).
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLKEM_NVS_H
#define MLKEM_NVS_H

#include <Preferences.h>
#include <stdint.h>
#include <string.h>
#include "MLKEM.h"

template <class KEM>
class MLKEM_NVS {
public:
  /*
   * Save a full keypair.
   * ns: NVS namespace (max 15 chars). Returns true on success.
   *
   * Any key previously stored in the namespace is removed *before* the new
   * one is written: the default NVS partition is only 20 KB, and a full
   * keypair (2.4-4.7 KB) could otherwise not always be overwritten in place.
   * If saving fails, the namespace holds no key.
   */
  static bool saveKeypair(const char *ns, const uint8_t *pk,
                          const uint8_t *sk) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return false;
    }
    prefs.remove("seed");
    prefs.remove("pk");
    prefs.remove("sk");
    bool ok = prefs.putUShort("lvl", KEM::PARAMETER_SET) == sizeof(uint16_t) &&
              prefs.putBytes("pk", pk, KEM::PUBLIC_KEY_SIZE) == KEM::PUBLIC_KEY_SIZE &&
              prefs.putBytes("sk", sk, KEM::SECRET_KEY_SIZE) == KEM::SECRET_KEY_SIZE;
    prefs.end();
    return ok;
  }

  /*
   * Save only the 64-byte keypair seed (d || z).
   * Any full keypair previously stored in the namespace is removed.
   */
  static bool saveSeed(const char *ns, const uint8_t *seed) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return false;
    }
    prefs.remove("pk");
    prefs.remove("sk");
    bool ok = prefs.putUShort("lvl", KEM::PARAMETER_SET) == sizeof(uint16_t) &&
              prefs.putBytes("seed", seed, KEM::KEYPAIR_SEED_SIZE) ==
                  KEM::KEYPAIR_SEED_SIZE;
    prefs.end();
    return ok;
  }

  /*
   * Load a keypair, in whichever format it was saved. A seed is expanded to
   * the full keypair. Returns true only if a keypair of this parameter set
   * was found and the secret key passes the FIPS 203 hash check.
   * On failure, sk is zeroized.
   */
  static bool loadKeypair(const char *ns, uint8_t *pk, uint8_t *sk) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    bool ok = false;
    if (prefs.getUShort("lvl", 0) == KEM::PARAMETER_SET) {
      if (prefs.isKey("seed")) {
        uint8_t seed[KEM::KEYPAIR_SEED_SIZE];
        ok = prefs.getBytes("seed", seed, sizeof(seed)) == sizeof(seed) &&
             KEM::generateKeypairFromSeed(pk, sk, seed) == 0;
        wipe(seed, sizeof(seed));
      } else {
        ok = prefs.getBytes("pk", pk, KEM::PUBLIC_KEY_SIZE) == KEM::PUBLIC_KEY_SIZE &&
             prefs.getBytes("sk", sk, KEM::SECRET_KEY_SIZE) == KEM::SECRET_KEY_SIZE &&
             KEM::checkSecretKey(sk) == 0 &&
             /* the public key is embedded in sk (FIPS 203 Alg. 16) */
             memcmp(pk, sk + 384 * (KEM::PUBLIC_KEY_SIZE / 384),
                    KEM::PUBLIC_KEY_SIZE) == 0;
      }
    }
    prefs.end();
    if (!ok) {
      wipe(sk, KEM::SECRET_KEY_SIZE);
    }
    return ok;
  }

  /*
   * Load only the public key. With seed storage the full keypair has to be
   * derived, so sk_scratch (SECRET_KEY_SIZE bytes) is needed in that case;
   * pass nullptr if you know the full keypair format is used.
   */
  static bool loadPublicKey(const char *ns, uint8_t *pk,
                            uint8_t *sk_scratch = nullptr) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    bool ok = false;
    if (prefs.getUShort("lvl", 0) == KEM::PARAMETER_SET) {
      if (prefs.isKey("pk")) {
        ok = prefs.getBytes("pk", pk, KEM::PUBLIC_KEY_SIZE) == KEM::PUBLIC_KEY_SIZE &&
             KEM::checkPublicKey(pk) == 0;
      } else if (sk_scratch != nullptr && prefs.isKey("seed")) {
        uint8_t seed[KEM::KEYPAIR_SEED_SIZE];
        ok = prefs.getBytes("seed", seed, sizeof(seed)) == sizeof(seed) &&
             KEM::generateKeypairFromSeed(pk, sk_scratch, seed) == 0;
        wipe(seed, sizeof(seed));
        wipe(sk_scratch, KEM::SECRET_KEY_SIZE);
      }
    }
    prefs.end();
    return ok;
  }

  /* True if a keypair (any format) of this parameter set is stored. */
  static bool hasKeypair(const char *ns) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    bool has = prefs.getUShort("lvl", 0) == KEM::PARAMETER_SET &&
               (prefs.isKey("seed") || (prefs.isKey("pk") && prefs.isKey("sk")));
    prefs.end();
    return has;
  }

  /* Remove all key material from the namespace. */
  static bool eraseKeypair(const char *ns) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return false;
    }
    prefs.remove("pk");
    prefs.remove("sk");
    prefs.remove("seed");
    prefs.remove("lvl");
    prefs.end();
    return true;
  }

  /*
   * Generate a new keypair and save it.
   *
   * seedOnly = false: store the full keypair.
   * seedOnly = true:  store only the 64-byte seed it was derived from.
   *
   * Returns 0 on success, negative on keygen error, 1 on NVS save error.
   */
  static int generateAndSave(const char *ns, uint8_t *pk, uint8_t *sk,
                             bool seedOnly = false) {
    int ret;
    if (!seedOnly) {
      ret = KEM::generateKeypair(pk, sk);
      if (ret != 0) {
        return ret;
      }
      return saveKeypair(ns, pk, sk) ? 0 : 1;
    }

    uint8_t seed[KEM::KEYPAIR_SEED_SIZE];
    ret = mlkem_esp32_randombytes(seed, sizeof(seed)) == 0
              ? KEM::generateKeypairFromSeed(pk, sk, seed)
              : MLK_ERR_RNG_FAIL;
    if (ret == 0 && !saveSeed(ns, seed)) {
      ret = 1;
    }
    wipe(seed, sizeof(seed));
    return ret;
  }

private:
  static void wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) {
      *v++ = 0;
    }
  }
};

typedef MLKEM_NVS<MLKEM512> MLKEM512_NVS;
typedef MLKEM_NVS<MLKEM768> MLKEM768_NVS;
typedef MLKEM_NVS<MLKEM1024> MLKEM1024_NVS;

#endif /* MLKEM_NVS_H */
