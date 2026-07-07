#ifndef FIPS204_IMPLEMENTATION_H
#define FIPS204_IMPLEMENTATION_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Generate an ML-DSA key pair for the current run.
 *
 * Derives and stores the public and secret keys in module-local buffers.
 *
 * @return int 0 on success.
 */
int fips204_generate_keys(void);

/**
 * @brief Sign the internally-stored message using the ML-DSA secret key.
 *
 * Produces the signature in the module-local signature buffer.
 *
 * @return int 0 on success, -1 on failure.
 */
int fips204_sign(void);

/**
 * @brief Verify the stored signature against the stored public key.
 *
 * Uses the module-local message buffer as verification input.
 *
 * @return int 0 when the signature is valid, -1 otherwise.
 */
int fips204_verify(void);

/**
 * @brief Clear stored ML-DSA state (keys, signature, message).
 *
 * Resets module-local buffers so subsequent runs start from a clean state.
 */
void fips204_reset_state(void);

/**
 * @brief Return pointer to the stored ML-DSA public key.
 *
 * @return const uint8_t* Pointer to public key bytes.
 */
const uint8_t *fips204_get_public_key(void);

/**
 * @brief Return the length of the stored ML-DSA public key.
 *
 * @return size_t Public key length in bytes.
 */
size_t fips204_get_public_key_len(void);

/**
 * @brief Return pointer to the stored ML-DSA signature.
 *
 * @return const uint8_t* Pointer to signature bytes.
 */
const uint8_t *fips204_get_signature(void);

/**
 * @brief Return the length of the stored ML-DSA signature.
 *
 * @return size_t Signature length in bytes.
 */
size_t fips204_get_signature_len(void);

/**
 * @brief Return pointer to the stored ML-DSA message buffer.
 *
 * @return const uint8_t* Pointer to message bytes used for the last sign.
 */
const uint8_t *fips204_get_message(void);

/**
 * @brief Return the length of the stored ML-DSA message.
 *
 * @return size_t Message length in bytes.
 */
size_t fips204_get_message_len(void);

#endif
