#ifndef ECDSA_IMPLEMENTATION_H
#define ECDSA_IMPLEMENTATION_H

#include <mbedtls/ecdsa.h>
#include <stddef.h>

/**
 * @brief Generate a fresh ECDSA key pair (secp256r1).
 *
 * Initializes and populates the provided ECDSA context with a new
 * keypair. Intended for use before signing or verification operations.
 *
 * @param [in,out] ctx Pointer to an mbedtls_ecdsa_context to initialize.
 * @return int 0 on success, negative mbedTLS error code on failure.
 */
int ecdsa_generate_keys(mbedtls_ecdsa_context *ctx);

/**
 * @brief Sign a message using the active ECDSA private key.
 *
 * Hashes the input message and produces a raw 64-byte r||s signature in
 * the output buffer.
 *
 * @param [in] ctx Active ECDSA context containing the private key.
 * @param [in] message Message bytes to be signed.
 * @param [in] message_len Length of the message in bytes.
 * @param [out] signature Buffer that receives the 64-byte signature (r||s).
 * @param [out] sig_len Receives the number of written signature bytes.
 * @return int 0 on success, negative value on error.
 */
int ecdsa_sign(mbedtls_ecdsa_context *ctx,
               const unsigned char *message,
               size_t message_len,
               unsigned char *signature,
               size_t *sig_len);

/**
 * @brief Verify a 64-byte r||s signature against the given message.
 *
 * Reconstructs the r and s components from the transport format, hashes the
 * message, and verifies the signature against the public key in @p ctx.
 *
 * @param [in] ctx Active ECDSA context with the public key.
 * @param [in] message Message bytes that were signed.
 * @param [in] message_len Length of the message in bytes.
 * @param [in] signature Raw 64-byte r||s signature buffer.
 * @param [in] sig_len Length of the signature buffer (expected 64).
 * @return int 0 when the signature is valid, negative on error or invalid.
 */
int ecdsa_verify(mbedtls_ecdsa_context *ctx,
                 const unsigned char *message,
                 size_t message_len,
                 const unsigned char *signature,
                 size_t sig_len);

/**
 * @brief Free ECDSA and RNG resources associated with the context.
 *
 * Releases internal mbedTLS structures and resets any shared RNG state.
 *
 * @param [in,out] ctx Context to free; may be NULL.
 * @return void
 */
void ecdsa_free(mbedtls_ecdsa_context *ctx);

#endif // ECDSA_IMPLEMENTATION_H
