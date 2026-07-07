#include "RSAPSS_implementation.h"
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <string.h>
#include <stdio.h>
#include "USBcommunication.h"


// Global RNG context used by the RSA-PSS helpers.
static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context ctr_drbg;
static int rng_initialized;

/**
 * @brief Format and print an mbedTLS error.
 *
 * Converts a negative error code into a readable hex message and sends it
 * to the USB console.
 *
 * @param[in] context Operation name
 * @param[in] err mbedTLS error code
 */
static void report_mbedtls_error(const char *context, int err)
{
    char msg[96];
    snprintf(msg, sizeof(msg), "%s failed: 0x%04X", context, (unsigned int) (-err));
    USB_print(msg);
}

/**
 * @brief Initialize the RNG context used by RSA-PSS.
 *
 * Sets up entropy and DRBG once and reuses them for later calls.
 *
 * @return int 0 on success, non-zero on failure
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

    const char *pers = "rsa_pss_demo";  // Personalization string for DRBG seeding
    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
            (const unsigned char *) pers, strlen(pers));
    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_ctr_drbg_seed", ret);
        return ret;
    }

    rng_initialized = 1;
    return 0;
}

// ---------------- KEYGEN ----------------

/**
 * @brief Generate an RSA-2048 keypair.
 *
 * Initializes the key context, applies PSS padding and creates the key.
 *
 * @param[out] rsa Destination RSA context
 * @return int 0 on success, non-zero on failure
 */
int rsa_pss_generate_keys(mbedtls_rsa_context *rsa)
{
    int ret;

    if (rsa == NULL)
    {
        USB_print("rsa_pss_generate_keys: rsa is NULL");
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    ret = init_rng();
    if (ret != 0)
    {
        return ret;
    }

    mbedtls_rsa_init(rsa);
    mbedtls_rsa_set_padding(rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);  // Configure RSA context for PSS with SHA-256

    ret = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);    // Generate a 2048-bit RSA key with public exponent 65537.
    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_rsa_gen_key", ret);
        return ret;
    }

    ret = mbedtls_rsa_check_privkey(rsa);
    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_rsa_check_privkey", ret);
        return ret;
    }

    return 0;
}

// ---------------- SIGN ----------------

/**
 * @brief Sign a message using RSA-PSS.
 *
 * Hashes the message with SHA-256 and writes the signature buffer.
 *
 * @param[in] rsa Initialized RSA context
 * @param[in] message Data to sign
 * @param[in] message_len Length of data to sign
 * @param[out] signature Output buffer for signature
 * @param[out] sig_len Output length pointer for signature
 * @return int 0 on success, non-zero on failure
 */
int rsa_pss_sign(mbedtls_rsa_context *rsa,
                 const unsigned char *message, size_t message_len,
                 unsigned char *signature, size_t *sig_len)
{
    int ret;
    unsigned char hash[32]; // SHA-256 digest of the message.

    if (rsa == NULL || message == NULL || signature == NULL || sig_len == NULL)
    {
        USB_print("rsa_pss_sign: invalid argument");
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    ret = init_rng();
    if (ret != 0)
    {
        return ret;
    }

    // Hash first so the RSA-PSS call signs a fixed-size digest.
    mbedtls_sha256(message, message_len, hash, 0);

    // Sign the digest with the configured RSA-PSS parameters.
    ret = mbedtls_rsa_rsassa_pss_sign(rsa,
            mbedtls_ctr_drbg_random, &ctr_drbg,
            MBEDTLS_MD_SHA256,
            sizeof(hash),
            hash,
            signature);
    if (ret == 0)
    {
        *sig_len = mbedtls_rsa_get_len(rsa);
    }
    else
    {
        report_mbedtls_error("mbedtls_rsa_rsassa_pss_sign", ret);
    }

    return ret;
}

// ---------------- VERIFY ----------------

/**
 * @brief Verify a message using RSA-PSS.
 *
 * Hashes the message and checks it against the provided signature.
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
                   const unsigned char *signature, size_t sig_len)
{
    int ret;
    unsigned char hash[32]; // SHA-256 digest of the message.

    if (rsa == NULL || message == NULL || signature == NULL)
    {
        USB_print("rsa_pss_verify: invalid argument");
        return MBEDTLS_ERR_RSA_BAD_INPUT_DATA;
    }

    if (sig_len != mbedtls_rsa_get_len(rsa))
    {
        USB_print("rsa_pss_verify: signature length mismatch");
        return MBEDTLS_ERR_RSA_VERIFY_FAILED;
    }

    // Recreate the digest so verification matches the signing step.
    mbedtls_sha256(message, message_len, hash, 0);

    // Verify the RSA-PSS signature against the digest.
    ret = mbedtls_rsa_rsassa_pss_verify(rsa,
            MBEDTLS_MD_SHA256,
            sizeof(hash),
            hash,
            signature);
    if (ret != 0)
    {
        report_mbedtls_error("mbedtls_rsa_rsassa_pss_verify", ret);
    }

    return ret;
}

/**
 * @brief Release RSA-PSS resources.
 *
 * Frees the RSA context and the shared entropy/DRBG state.
 *
 * @param[in] rsa RSA context to free
 */
void rsa_free(mbedtls_rsa_context *rsa)
{
    mbedtls_rsa_free(rsa);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    rng_initialized = 0;
}