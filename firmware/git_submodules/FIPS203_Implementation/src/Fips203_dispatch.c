#include "Fips203_implementation.h"

/**
 * @brief Compile-time dispatch for the FIPS203 backend.
 *
 * The CMake-selected macro chooses either the mock implementation or the real
 * ML-KEM bridge without adding runtime branching to the test flow.
 */

// C-linkage prototypes for the two backend implementations. 
extern int fips203_real_keygen(const uint8_t seed_d[FIPS203_SEED_D_BYTE_LEN],
                               const uint8_t seed_z[FIPS203_SEED_Z_BYTE_LEN],
                               fips203_public_key_t *pubkey,
                               fips203_secret_key_t *seckey);

extern int fips203_real_encapsulate(const uint8_t seed_m[FIPS203_SEED_M_BYTE_LEN],
                                    const fips203_public_key_t *pubkey,
                                    fips203_cipher_text_t *ciphertext,
                                    fips203_shared_secret_t *shared_secret);

extern int fips203_real_decapsulate(const fips203_secret_key_t *seckey,
                                    const fips203_cipher_text_t *ciphertext,
                                    fips203_shared_secret_t *shared_secret);

extern int fips203_mock_keygen(const uint8_t seed_d[FIPS203_SEED_D_BYTE_LEN],
                               const uint8_t seed_z[FIPS203_SEED_Z_BYTE_LEN],
                               fips203_public_key_t *pubkey,
                               fips203_secret_key_t *seckey);

extern int fips203_mock_encapsulate(const uint8_t seed_m[FIPS203_SEED_M_BYTE_LEN],
                                    const fips203_public_key_t *pubkey,
                                    fips203_cipher_text_t *ciphertext,
                                    fips203_shared_secret_t *shared_secret);

extern int fips203_mock_decapsulate(const fips203_secret_key_t *seckey,
                                    const fips203_cipher_text_t *ciphertext,
                                    fips203_shared_secret_t *shared_secret);

// Public API selection based on the build-time backend choice. 
#ifndef USE_FIPS203_MOCK
#define USE_FIPS203_MOCK 0
#endif

#if USE_FIPS203_MOCK
int fips203_keygen(const uint8_t seed_d[FIPS203_SEED_D_BYTE_LEN],
                   const uint8_t seed_z[FIPS203_SEED_Z_BYTE_LEN],
                   fips203_public_key_t *pubkey,
                   fips203_secret_key_t *seckey)
{
    // Route key generation to the selected backend. 
    return fips203_mock_keygen(seed_d, seed_z, pubkey, seckey);
}

int fips203_encapsulate(const uint8_t seed_m[FIPS203_SEED_M_BYTE_LEN],
                        const fips203_public_key_t *pubkey,
                        fips203_cipher_text_t *ciphertext,
                        fips203_shared_secret_t *shared_secret)
{
    // Route encapsulation to the selected backend. 
    return fips203_mock_encapsulate(seed_m, pubkey, ciphertext, shared_secret);
}

int fips203_decapsulate(const fips203_secret_key_t *seckey,
                        const fips203_cipher_text_t *ciphertext,
                        fips203_shared_secret_t *shared_secret)
{
    // Route decapsulation to the selected backend. 
    return fips203_mock_decapsulate(seckey, ciphertext, shared_secret);
}
#else

int fips203_keygen(const uint8_t seed_d[FIPS203_SEED_D_BYTE_LEN],
                   const uint8_t seed_z[FIPS203_SEED_Z_BYTE_LEN],
                   fips203_public_key_t *pubkey,
                   fips203_secret_key_t *seckey)
{
    // Route key generation to the selected backend. 
    return fips203_real_keygen(seed_d, seed_z, pubkey, seckey);
}

int fips203_encapsulate(const uint8_t seed_m[FIPS203_SEED_M_BYTE_LEN],
                        const fips203_public_key_t *pubkey,
                        fips203_cipher_text_t *ciphertext,
                        fips203_shared_secret_t *shared_secret)
{
    // Route encapsulation to the selected backend. 
    return fips203_real_encapsulate(seed_m, pubkey, ciphertext, shared_secret);
}

int fips203_decapsulate(const fips203_secret_key_t *seckey,
                        const fips203_cipher_text_t *ciphertext,
                        fips203_shared_secret_t *shared_secret)
{
    // Route decapsulation to the selected backend. 
    return fips203_real_decapsulate(seckey, ciphertext, shared_secret);
}

#endif
