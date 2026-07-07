#include "Fips203_implementation.h"
#include "ml_kem/ml_kem_768.hpp"
#include <span>

extern "C" {

/**
 * @brief Generate a ML-KEM-768 key pair. (not Mock)
 *
 * Bridges the C API to the C++ implementation used for the production path.
 *
 * @param [in] seed_d Deterministic private-key seed.
 * @param [in] seed_z Deterministic public-key seed.
 * @param [out] pubkey Destination public key buffer.
 * @param [out] seckey Destination secret key buffer.
 * @return 0 on success or -1 on invalid input.
 */
int fips203_real_keygen(const uint8_t seed_d[FIPS203_SEED_D_BYTE_LEN],
                        const uint8_t seed_z[FIPS203_SEED_Z_BYTE_LEN],
                        fips203_public_key_t *pubkey,
                        fips203_secret_key_t *seckey)
{
    if (!seed_d || !seed_z || !pubkey || !seckey) return -1;
    ml_kem_768::keygen(
            std::span<const uint8_t, 32>(seed_d, 32),
            std::span<const uint8_t, 32>(seed_z, 32),
            std::span<uint8_t, 1184>(pubkey->data, 1184),
            std::span<uint8_t, 2400>(seckey->data, 2400)
    );
    return 0;
}

/**
 * @brief Encapsulate against a ML-KEM-768 public key.
 *
 * @param [in] seed_m Deterministic message seed.
 * @param [in] pubkey Public key to encapsulate against.
 * @param [out] ciphertext Destination ciphertext buffer.
 * @param [out] shared_secret Destination shared secret buffer.
 * @return 0 on success or -1 on invalid input / encapsulation failure.
 */
int fips203_real_encapsulate(const uint8_t seed_m[FIPS203_SEED_M_BYTE_LEN],
                             const fips203_public_key_t *pubkey,
                             fips203_cipher_text_t *ciphertext,
                             fips203_shared_secret_t *shared_secret)
{
    if (!seed_m || !pubkey || !ciphertext || !shared_secret) return -1;
    bool success = ml_kem_768::encapsulate(
            std::span<const uint8_t, 32>(seed_m, 32),
            std::span<const uint8_t, 1184>(pubkey->data, 1184),
            std::span<uint8_t, 1088>(ciphertext->data, 1088),
            std::span<uint8_t, 32>(shared_secret->data, 32)
    );
    return success ? 0 : -1;
}

/**
 * @brief Decapsulate a ML-KEM-768 ciphertext.
 *
 * @param [in] seckey Secret key used for decapsulation.
 * @param [in] ciphertext Ciphertext received from the peer.
 * @param [out] shared_secret Destination shared secret buffer.
 * @return 0 on success or -1 on invalid input.
 */
int fips203_real_decapsulate(const fips203_secret_key_t *seckey,
                             const fips203_cipher_text_t *ciphertext,
                             fips203_shared_secret_t *shared_secret)
{
    if (!ciphertext || !seckey || !shared_secret) return -1;
    ml_kem_768::decapsulate(
            std::span<const uint8_t, 2400>(seckey->data, 2400),
            std::span<const uint8_t, 1088>(ciphertext->data, 1088),
            std::span<uint8_t, 32>(shared_secret->data, 32)
    );
    return 0;
}

}
