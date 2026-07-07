#include "Fips203_implementation.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

/**
 * @brief Blend one byte with a salt for deterministic mock output.
 *
 * @param [in] value Input byte.
 * @param [in] salt Salt byte used to vary the output.
 * @return Mixed byte value.
 */
static uint8_t mix_byte(uint8_t value, uint8_t salt)
{
    uint8_t mixed = (uint8_t)(value ^ salt);
    mixed = (uint8_t)((mixed << 3) | (mixed >> 5));
    return (uint8_t)(mixed + 0x5Du);
}

/**
 * @brief Build a deterministic mock FIPS203 key pair.
 *
 * @param [in] seed_d Deterministic private-key seed.
 * @param [in] seed_z Deterministic public-key seed.
 * @param [out] pubkey Destination public key buffer.
 * @param [out] seckey Destination secret key buffer.
 * @return 0 on success or a negative errno value on failure.
 */
int fips203_mock_keygen(const uint8_t seed_d[FIPS203_SEED_D_BYTE_LEN],
                        const uint8_t seed_z[FIPS203_SEED_Z_BYTE_LEN],
                        fips203_public_key_t *pubkey,
                        fips203_secret_key_t *seckey)
{
    size_t index;

    if (seed_d == NULL || seed_z == NULL || pubkey == NULL || seckey == NULL)
    {
        return -EINVAL;
    }

    // Build the public key by mixing the two seeds together in a deterministic way.
    for (index = 0; index < FIPS203_PKEY_BYTE_LEN; index++)
    {
        uint8_t d = seed_d[index % FIPS203_SEED_D_BYTE_LEN];
        uint8_t z = seed_z[index % FIPS203_SEED_Z_BYTE_LEN];
        pubkey->data[index] = mix_byte((uint8_t)(d + (uint8_t) index), z);
    }

    // Build the secret key by embedding the seeds and public key, then filling the rest with mixed values.
    memset(seckey->data, 0, sizeof(seckey->data));
    memcpy(seckey->data, seed_d, FIPS203_SEED_D_BYTE_LEN);
    memcpy(seckey->data + FIPS203_SEED_D_BYTE_LEN, seed_z, FIPS203_SEED_Z_BYTE_LEN);
    memcpy(seckey->data + 64, pubkey->data, FIPS203_PKEY_BYTE_LEN);

    // Fill the remaining bytes of the secret key with a mix of the seeds and public key for deterministic content.
    for (index = 64 + FIPS203_PKEY_BYTE_LEN; index < FIPS203_SKEY_BYTE_LEN; index++)
    {
        uint8_t base = seckey->data[index % 64];
        seckey->data[index] = mix_byte(base, (uint8_t) index);
    }

    return 0;
}

/**
 * @brief Build a deterministic mock encapsulation result.
 *
 * @param [in] seed_m Deterministic message seed.
 * @param [in] pubkey Public key to encapsulate against.
 * @param [out] cipher Destination ciphertext buffer.
 * @param [out] shared_secret Destination shared secret buffer.
 * @return 0 on success or a negative errno value on failure.
 */
int fips203_mock_encapsulate(const uint8_t seed_m[FIPS203_SEED_M_BYTE_LEN],
                             const fips203_public_key_t *pubkey,
                             fips203_cipher_text_t *cipher,
                             fips203_shared_secret_t *shared_secret)
{
    size_t index;

    if (seed_m == NULL || pubkey == NULL || cipher == NULL || shared_secret == NULL)
    {
        return -EINVAL;
    }

    // Build the ciphertext by mixing the message seed with the public key in a deterministic way.
    for (index = 0; index < FIPS203_CIPHER_TEXT_BYTE_LEN; index++)
    {
        uint8_t m = seed_m[index % FIPS203_SEED_M_BYTE_LEN];
        uint8_t p = pubkey->data[index % FIPS203_PKEY_BYTE_LEN];
        cipher->data[index] = (uint8_t)(m ^ p);
    }

    // Build the shared secret by further mixing the message seed with the public key.
    for (index = 0; index < FIPS203_SHARED_SECRET_BYTE_LEN; index++)
    {
        uint8_t m = seed_m[index];
        uint8_t p = pubkey->data[index];
        shared_secret->data[index] = mix_byte((uint8_t)(m ^ p), (uint8_t)(index * 11u + 7u));
    }

    return 0;
}

/**
 * @brief Recover the mock shared secret from a ciphertext.
 *
 * @param [in] seckey Secret key used for decapsulation.
 * @param [in] cipher Ciphertext received from the peer.
 * @param [out] shared_secret Destination shared secret buffer.
 * @return 0 on success or a negative errno value on failure.
 */
int fips203_mock_decapsulate(const fips203_secret_key_t *seckey,
                             const fips203_cipher_text_t *cipher,
                             fips203_shared_secret_t *shared_secret)
{
    size_t index;
    uint8_t recovered_m[FIPS203_SEED_M_BYTE_LEN];
    const uint8_t *pubkey_in_seckey;

    if (seckey == NULL || cipher == NULL || shared_secret == NULL)
    {
        return -EINVAL;
    }

    pubkey_in_seckey = seckey->data + 64;

    for (index = 0; index < FIPS203_SEED_M_BYTE_LEN; index++)
    {
        recovered_m[index] = (uint8_t)(cipher->data[index] ^ pubkey_in_seckey[index]);
    }

    // Reconstruct the shared secret using the recovered message and the public key from the secret key.
    for (index = 0; index < FIPS203_SHARED_SECRET_BYTE_LEN; index++)
    {
        uint8_t m = recovered_m[index];
        uint8_t p = pubkey_in_seckey[index];
        shared_secret->data[index] = mix_byte((uint8_t)(m ^ p), (uint8_t)(index * 11u + 7u));
    }

    return 0;
}

int fips203_shared_secret_to_string(const fips203_shared_secret_t *shared_secret,
                                    char *out,
                                    size_t out_size)
{
    size_t index;
    int written;

    if (shared_secret == NULL || out == NULL)
    {
        return -EINVAL;
    }

    if (out_size < (FIPS203_SHARED_SECRET_BYTE_LEN * 2u + 1u))
    {
        return -ENOSPC;
    }

    for (index = 0; index < FIPS203_SHARED_SECRET_BYTE_LEN; index++)
    {
        written = snprintf(out + (index * 2u), out_size - (index * 2u), "%02X", shared_secret->data[index]);
        if (written != 2)
        {
            return -EINVAL;
        }
    }

    out[FIPS203_SHARED_SECRET_BYTE_LEN * 2u] = '\0';
    return 0;
}
