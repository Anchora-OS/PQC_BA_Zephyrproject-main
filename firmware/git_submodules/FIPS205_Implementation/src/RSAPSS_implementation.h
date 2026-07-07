#ifndef RSA_PSS_IMPLEMENTATION_H
#define RSA_PSS_IMPLEMENTATION_H

#include <mbedtls/rsa.h>
#include <stddef.h>

/**
 * @brief Generate an RSA-2048 keypair configured for PSS/SHA-256.
 *
 * @param[out] rsa Initialized RSA context to receive the new keypair
 * @return int 0 on success, non-zero on failure
 */
int rsa_pss_generate_keys(mbedtls_rsa_context *rsa);

/**
 * @brief Sign a message using RSA-PSS (SHA-256).
 *
 * Hashes the input with SHA-256 and produces a PSS signature.
 *
 * @param[in] rsa Initialized RSA context
 * @param[in] message Data to sign
 * @param[in] message_len Length of data to sign
 * @param[out] signature Output buffer for the signature
 * @param[out] sig_len Pointer to receive signature length
 * @return int 0 on success, non-zero on failure
 */
int rsa_pss_sign(mbedtls_rsa_context *rsa,
                 const unsigned char *message, size_t message_len,
                 unsigned char *signature, size_t *sig_len);

/**
 * @brief Verify an RSA-PSS signature.
 *
 * @param[in] rsa Initialized RSA context
 * @param[in] message Signed data
 * @param[in] message_len Length of signed data
 * @param[in] signature Signature buffer
 * @param[in] sig_len Signature length
 * @return int 0 on success, non-zero on failure
 */
int rsa_pss_verify(mbedtls_rsa_context *rsa,
                   const unsigned char *message, size_t message_len,
                   const unsigned char *signature, size_t sig_len);

/**
 * @brief Free RSA and RNG resources used by the RSA-PSS helpers.
 *
 * Frees the provided RSA context and releases the shared CTR-DRBG/entropy
 * state used by this module.
 *
 * @param[in] rsa RSA context to free
 */
void rsa_free(mbedtls_rsa_context *rsa);

#endif // RSA_PSS_IMPLEMENTATION_H
