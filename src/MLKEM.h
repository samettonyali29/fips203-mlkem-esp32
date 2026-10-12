/*
 * MLKEM.h - Arduino-friendly C++ wrapper for ML-KEM (FIPS 203)
 *
 * Usage:
 *   #include <MLKEM.h>          // or <MLKEM512.h>, <MLKEM768.h>, <MLKEM1024.h>
 *
 *   uint8_t pk[MLKEM768::PUBLIC_KEY_SIZE], sk[MLKEM768::SECRET_KEY_SIZE];
 *   uint8_t ct[MLKEM768::CIPHERTEXT_SIZE];
 *   uint8_t ss_alice[MLKEM768::SHARED_SECRET_SIZE];
 *   uint8_t ss_bob[MLKEM768::SHARED_SECRET_SIZE];
 *
 *   MLKEM768::generateKeypair(pk, sk);        // Alice
 *   MLKEM768::encapsulate(ct, ss_bob, pk);    // Bob, sends ct to Alice
 *   MLKEM768::decapsulate(ss_alice, ct, sk);  // Alice
 *   // ss_alice == ss_bob
 *
 * MLKEM512, MLKEM768 and MLKEM1024 are aliases of MLKEM<512>, MLKEM<768>
 * and MLKEM<1024> and share exactly the same API. All functions return 0 on
 * success and a negative MLK_ERR_* code on failure.
 *
 * Copyright (c) 2026 The fips203-mlkem-esp32 authors
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLKEM_WRAPPER_H
#define MLKEM_WRAPPER_H

#include <stddef.h>
#include <stdint.h>
#include "mlkem_esp32.h"

namespace mlkem_esp32 {

/* Per-level binding to the C API. Not meant to be used directly. */
template <unsigned LEVEL>
struct Binding;

#define MLKEM_ESP32_BINDING(L)                                                \
  template <>                                                                 \
  struct Binding<L> {                                                         \
    static constexpr size_t PK = MLKEM##L##_PUBLICKEYBYTES;                   \
    static constexpr size_t SK = MLKEM##L##_SECRETKEYBYTES;                   \
    static constexpr size_t CT = MLKEM##L##_CIPHERTEXTBYTES;                  \
    static constexpr unsigned SECURITY_CATEGORY = (L) == 512 ? 1              \
                                                : (L) == 768 ? 3 : 5;         \
    static int keypair(uint8_t *pk, uint8_t *sk) {                            \
      return PQCP_MLKEM_NATIVE_MLKEM##L##_keypair(pk, sk);                    \
    }                                                                         \
    static int keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *c) {   \
      return PQCP_MLKEM_NATIVE_MLKEM##L##_keypair_derand(pk, sk, c);          \
    }                                                                         \
    static int enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {             \
      return PQCP_MLKEM_NATIVE_MLKEM##L##_enc(ct, ss, pk);                    \
    }                                                                         \
    static int enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk,        \
                          const uint8_t *c) {                                 \
      return PQCP_MLKEM_NATIVE_MLKEM##L##_enc_derand(ct, ss, pk, c);          \
    }                                                                         \
    static int dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {       \
      return PQCP_MLKEM_NATIVE_MLKEM##L##_dec(ss, ct, sk);                    \
    }                                                                         \
    static int check_pk(const uint8_t *pk) {                                 \
      return PQCP_MLKEM_NATIVE_MLKEM##L##_check_pk(pk);                       \
    }                                                                         \
    static int check_sk(const uint8_t *sk) {                                 \
      return PQCP_MLKEM_NATIVE_MLKEM##L##_check_sk(sk);                       \
    }                                                                         \
  };

MLKEM_ESP32_BINDING(512)
MLKEM_ESP32_BINDING(768)
MLKEM_ESP32_BINDING(1024)
#undef MLKEM_ESP32_BINDING

} /* namespace mlkem_esp32 */

template <unsigned LEVEL>
class MLKEM {
  typedef mlkem_esp32::Binding<LEVEL> B;

public:
  /* 512, 768 or 1024 */
  static constexpr unsigned PARAMETER_SET = LEVEL;
  /* NIST security category: 1 (~AES-128), 3 (~AES-192) or 5 (~AES-256) */
  static constexpr unsigned SECURITY_CATEGORY = B::SECURITY_CATEGORY;

  static constexpr size_t PUBLIC_KEY_SIZE    = B::PK; /* encapsulation key ek */
  static constexpr size_t SECRET_KEY_SIZE    = B::SK; /* decapsulation key dk */
  static constexpr size_t CIPHERTEXT_SIZE    = B::CT;
  static constexpr size_t SHARED_SECRET_SIZE = MLKEM_BYTES;        /* 32 */
  static constexpr size_t KEYPAIR_SEED_SIZE  = 2 * MLKEM_SYMBYTES; /* 64: d || z */
  static constexpr size_t ENCAPS_SEED_SIZE   = MLKEM_SYMBYTES;     /* 32: m */

  /*
   * Generate a new keypair using the ESP32 hardware RNG.
   *
   * pk: output, PUBLIC_KEY_SIZE bytes (share this)
   * sk: output, SECRET_KEY_SIZE bytes (keep this secret)
   *
   * Returns 0 on success, negative on error.
   */
  static int generateKeypair(uint8_t *pk, uint8_t *sk) {
    return B::keypair(pk, sk);
  }

  /*
   * Deterministically derive a keypair from a 64-byte seed d || z
   * (FIPS 203, ML-KEM.KeyGen_internal). The same seed always yields the
   * same keypair, so the seed is a compact (64-byte) backup of sk.
   *
   * Returns 0 on success, negative on error.
   */
  static int generateKeypairFromSeed(uint8_t *pk, uint8_t *sk,
                                     const uint8_t *seed) {
    return B::keypair_derand(pk, sk, seed);
  }

  /*
   * Encapsulate: create a fresh shared secret for the owner of pk.
   *
   * ct: output, CIPHERTEXT_SIZE bytes (send this to the key owner)
   * ss: output, SHARED_SECRET_SIZE bytes (keep this secret)
   * pk: the recipient's public key
   *
   * Returns 0 on success, MLK_ERR_INVALID_PK if pk fails the FIPS 203
   * modulus check, other negative values on error.
   */
  static int encapsulate(uint8_t *ct, uint8_t *ss, const uint8_t *pk) {
    return B::enc(ct, ss, pk);
  }

  /*
   * Deterministic encapsulation with caller-provided 32-byte randomness m
   * (FIPS 203, ML-KEM.Encaps_internal). For testing only -- reusing m
   * reuses the shared secret.
   */
  static int encapsulateFromSeed(uint8_t *ct, uint8_t *ss, const uint8_t *pk,
                                 const uint8_t *seed) {
    return B::enc_derand(ct, ss, pk, seed);
  }

  /*
   * Decapsulate: recover the shared secret from a ciphertext.
   *
   * ss: output, SHARED_SECRET_SIZE bytes
   * ct: ciphertext received from the encapsulating party
   * sk: own secret key
   *
   * Returns 0 on success, MLK_ERR_INVALID_SK if sk fails the FIPS 203 hash
   * check. Note: a tampered/invalid ciphertext does NOT produce an error;
   * ML-KEM uses implicit rejection and returns a pseudo-random ss that will
   * simply not match the sender's secret.
   */
  static int decapsulate(uint8_t *ss, const uint8_t *ct, const uint8_t *sk) {
    return B::dec(ss, ct, sk);
  }

  /*
   * Validate a received public key (FIPS 203 Section 7.2 modulus check).
   * encapsulate() performs this check itself.
   * Returns 0 if valid, MLK_ERR_INVALID_PK otherwise.
   */
  static int checkPublicKey(const uint8_t *pk) { return B::check_pk(pk); }

  /*
   * Validate a secret key (FIPS 203 Section 7.3 hash check), e.g. after
   * loading it from flash. decapsulate() performs this check itself.
   * Returns 0 if valid, MLK_ERR_INVALID_SK otherwise.
   */
  static int checkSecretKey(const uint8_t *sk) { return B::check_sk(sk); }
};

/* Pre-C++17 out-of-class definitions of the static constexpr members, so
 * that they may be ODR-used (e.g. bound to a const reference). */
#if __cplusplus < 201703L
template <unsigned L> constexpr unsigned MLKEM<L>::PARAMETER_SET;
template <unsigned L> constexpr unsigned MLKEM<L>::SECURITY_CATEGORY;
template <unsigned L> constexpr size_t MLKEM<L>::PUBLIC_KEY_SIZE;
template <unsigned L> constexpr size_t MLKEM<L>::SECRET_KEY_SIZE;
template <unsigned L> constexpr size_t MLKEM<L>::CIPHERTEXT_SIZE;
template <unsigned L> constexpr size_t MLKEM<L>::SHARED_SECRET_SIZE;
template <unsigned L> constexpr size_t MLKEM<L>::KEYPAIR_SEED_SIZE;
template <unsigned L> constexpr size_t MLKEM<L>::ENCAPS_SEED_SIZE;
#endif

typedef MLKEM<512> MLKEM512;
typedef MLKEM<768> MLKEM768;
typedef MLKEM<1024> MLKEM1024;

#endif /* MLKEM_WRAPPER_H */
