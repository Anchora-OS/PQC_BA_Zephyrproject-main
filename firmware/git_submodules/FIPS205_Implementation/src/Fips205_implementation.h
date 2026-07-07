#ifndef FIPS205_IMPLEMENTATION_H
#define FIPS205_IMPLEMENTATION_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate a FIPS205 (SLH-DSA) keypair.
 *
 * Calls the underlying SLH-DSA key generation with the chosen parameter set.
 *
 * @return int 0 on success, non-zero on failure
 */
int fips205_generate_keys(void);

/**
 * @brief Sign a fresh message using FIPS205 (SLH-DSA).
 *
 * Generates a random message, signs it with the secret key and stores the
 * signature for later retrieval.
 *
 * @return int 0 on success, -1 on failure
 */
int fips205_sign(void);

/**
 * @brief Verify the currently stored signature against the stored message.
 *
 * @return int 0 on success, -1 if no signature present, other non-zero on failure
 */
int fips205_verify(void);

const uint8_t *fips205_get_public_key(void);
const uint8_t *fips205_get_signature(void);
const uint8_t *fips205_get_message(void);

size_t fips205_get_public_key_len(void);
size_t fips205_get_signature_len(void);
size_t fips205_get_message_len(void);

#ifdef __cplusplus
}
#endif

#endif /* FIPS205_IMPLEMENTATION_H */
