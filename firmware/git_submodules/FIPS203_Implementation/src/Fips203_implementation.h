#ifndef FIPS203_IMPLEMENTATION_H
#define FIPS203_IMPLEMENTATION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ML-KEM-768 Constants */
#define FIPS203_SEED_D_BYTE_LEN 32
#define FIPS203_SEED_Z_BYTE_LEN 32
#define FIPS203_PKEY_BYTE_LEN 1184
#define FIPS203_SKEY_BYTE_LEN 2400
#define FIPS203_SEED_M_BYTE_LEN 32
#define FIPS203_CIPHER_TEXT_BYTE_LEN 1088
#define FIPS203_SHARED_SECRET_BYTE_LEN 32

/* ML-KEM-768 Key Types */
typedef struct
{
    uint8_t data[FIPS203_PKEY_BYTE_LEN];
} fips203_public_key_t;

typedef struct
{
    uint8_t data[FIPS203_SKEY_BYTE_LEN];
} fips203_secret_key_t;

typedef struct
{
    uint8_t data[FIPS203_CIPHER_TEXT_BYTE_LEN];
} fips203_cipher_text_t;

typedef struct
{
    uint8_t data[FIPS203_SHARED_SECRET_BYTE_LEN];
} fips203_shared_secret_t;

/**
 * @brief Generate a FIPS203 key pair.
 *
 * @param [in] seed_d Deterministic seed used for the private key path.
 * @param [in] seed_z Deterministic seed used for the public key path.
 * @param [out] pubkey Destination public key buffer.
 * @param [out] seckey Destination secret key buffer.
 * @return 0 on success or a negative errno value on failure.
 */
int fips203_keygen(const uint8_t seed_d[FIPS203_SEED_D_BYTE_LEN],
                   const uint8_t seed_z[FIPS203_SEED_Z_BYTE_LEN],
                   fips203_public_key_t *pubkey,
                   fips203_secret_key_t *seckey);

/**
 * @brief Encapsulate to a FIPS203 public key.
 *
 * @param [in] seed_m Deterministic message seed used for the encapsulation.
 * @param [in] pubkey Public key to encapsulate against.
 * @param [out] cipher Destination ciphertext buffer.
 * @param [out] shared_secret Destination shared secret buffer.
 * @return 0 on success or a negative errno value on failure.
 */
int fips203_encapsulate(const uint8_t seed_m[FIPS203_SEED_M_BYTE_LEN],
                        const fips203_public_key_t *pubkey,
                        fips203_cipher_text_t *cipher,
                        fips203_shared_secret_t *shared_secret);

/**
 * @brief Decapsulate a FIPS203 ciphertext.
 *
 * @param [in] seckey Secret key used for decapsulation.
 * @param [in] cipher Ciphertext received from the peer.
 * @param [out] shared_secret Destination shared secret buffer.
 * @return 0 on success or a negative errno value on failure.
 */
int fips203_decapsulate(const fips203_secret_key_t *seckey,
                        const fips203_cipher_text_t *cipher,
                        fips203_shared_secret_t *shared_secret);

/**
 * @brief Convert a FIPS203 shared secret to a hex/text string.
 *
 * Formats the `shared_secret` bytes into a human-readable textual
 * representation placed into `out`. The output is NUL-terminated when the
 * provided buffer is large enough.
 *
 * @param [in] shared_secret Pointer to the shared secret to format.
 * @param [out] out Destination buffer for the textual representation.
 * @param [in] out_size Size of the destination buffer in bytes.
 * @return 0 on success or a negative errno value if `out_size` is too small.
 */
int fips203_shared_secret_to_string(const fips203_shared_secret_t *shared_secret,
                                    char *out, size_t out_size);

#ifdef __cplusplus
}
#endif

#endif
