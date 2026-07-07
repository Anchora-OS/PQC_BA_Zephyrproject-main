#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <string.h>
#include <stdio.h>
#include "USBcommunication.h"
#include "ECDSA_implementation.h"


static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static int rng_initialized;

/**
 * @brief Report an mbedTLS error through the USB log.
 *
 * Converts the negative mbedTLS error code into a compact hex message so the
 * caller can see which primitive failed without changing control flow.
 *
 * @param [in] context Short label for the failing mbedTLS call.
 * @param [in] err Negative mbedTLS error code.
 * @return None.
 */
static void report_mbedtls_error(const char *context, int err)
{
    char msg[96];
    snprintf(msg, sizeof(msg), "%s failed: 0x%04X", context, (unsigned int) (-err));
    USB_print(msg);
}

/**
 * @brief Initialize the shared RNG used by the ECDSA path.
 *
 * Seeds the CTR-DRBG once and reuses it across later sign and keygen calls so
 * the ECDSA helpers can stay lightweight.
 *
 * @return int Returns 0 on success and the mbedTLS error code on failure.
 */
static int init_rng(void)
{
    int ret;

    if (rng_initialized)
    {
        return 0;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    const char *pers = "ecdsa_demo";

    // Use a fixed personalization string so the DRBG state is tied to this
    // firmware image and not to unrelated callers.
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            (const unsigned char *) pers,
            strlen(pers));

    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_ctr_drbg_seed", ret);
        return ret;
    }

    rng_initialized = 1;
    return 0;
}

// ---------------- KEY GENERATION ----------------

/**
 * @brief Generate a fresh ECDSA key pair.
 *
 * Allocates the context if needed and fills it with a secp256r1 key pair for
 * the current benchmark run.
 *
 * @param [in,out] ctx ECDSA context to initialize and populate.
 * @return int Returns 0 on success and a negative value on invalid input or
 *             mbedTLS failure.
 */
int ecdsa_generate_keys(mbedtls_ecdsa_context *ctx)
{
    int ret;

    if (ctx == NULL)
    {
        USB_print("ecdsa_generate_keys: ctx NULL");
        return -1;
    }

    ret = init_rng();
    if (ret != 0) return ret;

    mbedtls_ecdsa_init(ctx);

    ret = mbedtls_ecdsa_genkey(ctx,
            MBEDTLS_ECP_DP_SECP256R1,
            mbedtls_ctr_drbg_random,
            &ctr_drbg);

    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_ecdsa_genkey", ret);
        return ret;
    }

    USB_print("ECDSA keypair generated (secp256r1)");
    return 0;
}

// ---------------- SIGNING ----------------

/**
 * @brief Sign the current message buffer with the active ECDSA key.
 *
 * Hashes the raw message first so the signature input stays consistent with
 * the verify path, then writes the raw r||s signature into the output buffer.
 *
 * @param [in,out] ctx Active ECDSA context with a generated private key.
 * @param [in] message Message bytes to sign.
 * @param [in] message_len Length of the message in bytes.
 * @param [out] signature Output buffer that receives the 64-byte signature.
 * @param [out] sig_len Receives the written signature length.
 * @return int Returns 0 on success and a negative value on invalid input or
 *             mbedTLS failure.
 */
int ecdsa_sign(mbedtls_ecdsa_context *ctx,
               const unsigned char *message,
               size_t message_len,
               unsigned char *signature,
               size_t *sig_len)
{
    int ret;
    unsigned char hash[32];
    mbedtls_mpi r, s;
    size_t r_len = 0;
    size_t s_len = 0;

    if (!ctx || !message || !signature || !sig_len)
    {
        USB_print("ecdsa_sign: invalid args");
        return -1;
    }

    ret = init_rng();
    if (ret != 0) return ret;

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // Hash the raw message first because ECDSA operates on a digest, not the
    // original byte stream.
    mbedtls_sha256(message, message_len, hash, 0);

    // Sign the digest and keep the result in the intermediate r and s values.
    ret = mbedtls_ecdsa_sign(&ctx->MBEDTLS_PRIVATE(grp),
            &r,
            &s,
            &ctx->MBEDTLS_PRIVATE(d),
            hash,
            sizeof(hash),
            mbedtls_ctr_drbg_random,
            &ctr_drbg);

    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_ecdsa_sign", ret);
        goto cleanup;
    }

    // Convert r and s into the fixed-width transport format expected by the
    // host side parser.
    r_len = mbedtls_mpi_size(&r);
    s_len = mbedtls_mpi_size(&s);

    memset(signature, 0, 64);   // Clear the output buffer before writing the variable-length r and s values.

    // Write r and s into the output buffer with leading zero padding as needed to fit the fixed 32-byte width.
    ret = mbedtls_mpi_write_binary(&r, signature + (32 - r_len), r_len);
    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_mpi_write_binary(r)", ret);
        goto cleanup;
    }

    ret = mbedtls_mpi_write_binary(&s, signature + 32 + (32 - s_len), s_len);
    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_mpi_write_binary(s)", ret);
        goto cleanup;
    }

    *sig_len = 64;

    cleanup:
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

// ---------------- VERIFY ----------------

/**
 * @brief Verify an ECDSA signature against the active key and message.
 *
 * Rebuilds the r and s values from the raw transport buffer, hashes the
 * message in the same way as signing, and checks the signature against the
 * public key stored in the context.
 *
 * @param [in] ctx Active ECDSA context with the public key loaded.
 * @param [in] message Message bytes to verify.
 * @param [in] message_len Length of the message in bytes.
 * @param [in] signature Raw 64-byte r||s signature buffer.
 * @param [in] sig_len Signature length in bytes.
 * @return int Returns 0 when the signature is valid and a negative value on
 *             invalid input or verification failure.
 */
int ecdsa_verify(mbedtls_ecdsa_context *ctx,
                 const unsigned char *message,
                 size_t message_len,
                 const unsigned char *signature,
                 size_t sig_len)
{
    int ret;
    unsigned char hash[32];
    mbedtls_mpi r, s;

    if (!ctx || !message || !signature)
    {
        USB_print("ecdsa_verify: invalid args");
        return -1;
    }

    if (sig_len != 64)
    {
        USB_print("ecdsa_verify: invalid signature length");
        return -1;
    }

    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    // Rebuild the signature components from the flat transport buffer.
    ret = mbedtls_mpi_read_binary(&r, signature, 32);
    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_mpi_read_binary(r)", ret);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        return ret;
    }

    // The s value is located after r in the transport format.
    ret = mbedtls_mpi_read_binary(&s, signature + 32, 32);
    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_mpi_read_binary(s)", ret);
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        return ret;
    }

    // Hash the message the same way as the signing path.
    mbedtls_sha256(message, message_len, hash, 0);

    // Verify the digest against the public key already stored in the context.
    ret = mbedtls_ecdsa_verify(&ctx->MBEDTLS_PRIVATE(grp),
            hash,
            sizeof(hash),
            &ctx->MBEDTLS_PRIVATE(Q),
            &r,
            &s);

    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_ecdsa_verify", ret);
    }

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return ret;
}

// ---------------- CLEANUP ----------------

/**
 * @brief Release all ECDSA and RNG state used by the module.
 *
 * Clears the key context and resets the shared RNG bookkeeping so the next run
 * starts from a clean state.
 *
 * @param [in,out] ctx ECDSA context to free.
 * @return None.
 */
void ecdsa_free(mbedtls_ecdsa_context *ctx)
{
    mbedtls_ecdsa_free(ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    rng_initialized = 0;
}