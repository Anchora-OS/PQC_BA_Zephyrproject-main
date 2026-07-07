#include "Fips205_implementation.h"
#include <zephyr/random/random.h>
#include <string.h>
#include "Fips205_Files/slh_dsa.h"

// ---------------- CONFIG ----------------

// Example: SLH-DSA-SHA2-128s
#define PARAMS (&slh_dsa_sha2_128s)
#define FIPS205_PK_BYTES 32
#define FIPS205_SK_BYTES 64
#define FIPS205_SIG_BYTES 7856

// ---------------- GLOBAL STATE ----------------

static uint8_t pubkey[FIPS205_PK_BYTES];
static uint8_t seckey[FIPS205_SK_BYTES];
static uint8_t signature[FIPS205_SIG_BYTES];
static uint8_t message[32];
static size_t signature_len;

/**
 * @brief Generate random bytes for FIPS205 operations.
 *
 * Fills a buffer using Zephyr's random source.
 *
 * @param[out] buf Destination buffer
 * @param[in] len Number of bytes to generate
 * @return int Always returns 0
 */
static int fill_random(uint8_t *buf, size_t len)
{
    sys_rand_get(buf, len);
    return 0;
}

// ---------------- KEYGEN ----------------

/**
 * @brief Generate the FIPS205 keypair.
 *
 * Calls the SLH-DSA key generation routine with the fixed parameter set.
 *
 * @return int 0 on success, non-zero on failure
 */
int fips205_generate_keys(void)
{
    return slh_keygen(seckey, pubkey, fill_random, PARAMS);
}

// ---------------- SIGN ----------------

/**
 * @brief Sign the current FIPS205 message buffer.
 *
 * Generates fresh message bytes, signs them and stores the signature length.
 *
 * @return int 0 on success, -1 on failure
 */
int fips205_sign(void)
{
    fill_random(message, sizeof(message));

    signature_len = slh_sign(signature, message, sizeof(message), NULL, 0,
            seckey, NULL, PARAMS);
    return signature_len == 0 ? -1 : 0;
}

// ---------------- VERIFY ----------------

/**
 * @brief Verify the stored FIPS205 signature.
 *
 * Checks whether the signature matches the current message and public key.
 *
 * @return int 0 on success, -1 on missing signature, other non-zero on verify failure
 */
int fips205_verify(void)
{
    if (signature_len == 0)
    {
        return -1;
    }

    return slh_verify(message, sizeof(message), signature, signature_len,
            NULL, 0, pubkey, PARAMS);
}

// ---------------- GETTERS ----------------

/**
 * @brief Return the generated FIPS205 public key buffer.
 *
 * Provides a pointer to the in-memory public key for transport.
 *
 * @return const uint8_t* Pointer to public key bytes
 */
const uint8_t *fips205_get_public_key(void)
{ return pubkey; }

/**
 * @brief Return the generated FIPS205 signature buffer.
 *
 * Provides a pointer to the current signature bytes.
 *
 * @return const uint8_t* Pointer to signature bytes
 */
const uint8_t *fips205_get_signature(void)
{ return signature; }

/**
 * @brief Return the generated FIPS205 message buffer.
 *
 * Provides a pointer to the message that was signed.
 *
 * @return const uint8_t* Pointer to message bytes
 */
const uint8_t *fips205_get_message(void)
{ return message; }

/**
 * @brief Return the size of the public key buffer.
 *
 * Reports the key size for the current parameter set.
 *
 * @return size_t Public key length in bytes
 */
size_t fips205_get_public_key_len(void)
{
    return slh_pk_sz(PARAMS);
}

/**
 * @brief Return the size of the signature buffer.
 *
 * Reports the signature size or the current signature length if set.
 *
 * @return size_t Signature length in bytes
 */
size_t fips205_get_signature_len(void)
{
    return signature_len == 0 ? slh_sig_sz(PARAMS) : signature_len;
}

/**
 * @brief Return the size of the message buffer.
 *
 * Reports the fixed message buffer size used during signing.
 *
 * @return size_t Message length in bytes
 */
size_t fips205_get_message_len(void)
{
    return sizeof(message);
}
