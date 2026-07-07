#include "FiPS204_implementation.h"
#include <zephyr/random/random.h>
#include "ml_dsa/ml_dsa_65.hpp"
#include <array>
#include <string.h>
#include <vector>

// ---------------- CONFIG ----------------

static constexpr size_t MSG_LEN = 32;   // Fixed message length for signing and verification

// ---------------- GLOBAL STATE ----------------
// Module-local buffers to hold the current key, signature, and message for the
static std::array<uint8_t, ml_dsa_65::PubKeyByteLen> pubkey;
static std::array<uint8_t, ml_dsa_65::SecKeyByteLen> seckey;
static std::array<uint8_t, ml_dsa_65::SigByteLen> signature;

static std::array<uint8_t, MSG_LEN> message;

// ---------------- (Zephyr random) ----------------

/**
 * @brief Fill a buffer with entropy from Zephyr's random source.
 *
 * Keeps the module self-contained so the key generation and signing helpers
 * can request fresh randomness without dealing with the RNG backend directly.
 *
 * @param [out] buf Buffer to receive random bytes.
 * @param [in] len Number of bytes to fill.
 * @return None.
 */
static void fill_random(uint8_t *buf, size_t len)
{
    sys_rand_get(buf, len);
}

// ---------------- KEYGEN ----------------

/**
 * @brief Generate the ML-DSA key pair used by the current run.
 *
 * Fills a fresh seed, derives the public and secret keys, and stores them in
 * the module-local buffers for later signing and verification.
 *
 * @return int Returns 0 on success and never returns a partial result.
 */
int fips204_generate_keys(void)
{
    std::array<uint8_t, ml_dsa_65::KeygenSeedByteLen> seed{};

    // Generate a fresh seed so each benchmark run starts from a new key pair.
    fill_random(seed.data(), seed.size());

    ml_dsa_65::keygen(seed, pubkey, seckey);
    return 0;
}

// ---------------- SIGN ----------------

/**
 * @brief Sign the current ML-DSA message buffer.
 *
 * Uses a fresh per-signature randomness block and a fresh message so the
 * benchmark can measure a full sign operation instead of reusing prior state.
 *
 * @return int Returns 0 on success and -1 when the signing primitive rejects
 *             the input.
 */
int fips204_sign(void)
{
    std::array<uint8_t, ml_dsa_65::SigningSeedByteLen> rnd{};

    // Refresh both the per-signature randomness and the message buffer so the
    // signer and verifier operate on the same current-run data.
    fill_random(rnd.data(), rnd.size());
    fill_random(message.data(), message.size());

    std::vector<uint8_t> msg_vec(message.begin(), message.end());
    // Sign the message and store the result in the module-local signature buffer.
    bool ok = ml_dsa_65::sign(rnd, seckey, msg_vec, {}, signature);

    if (!ok)
    {
        return -1;
    }
    return 0;
}

// ---------------- VERIFY ----------------

/**
 * @brief Verify the stored ML-DSA signature against the stored public key.
 *
 * Rebuilds the message view from the module buffer so verification checks the
 * exact data that was just signed.
 *
 * @return int Returns 0 when the signature is valid and -1 otherwise.
 */
int fips204_verify(void)
{
    std::vector<uint8_t> msg_vec(message.begin(), message.end());

    bool valid = ml_dsa_65::verify(pubkey, msg_vec, {}, signature);

    if (!valid)
    {
        return -1;
    }
    return 0;
}

// ---------------- miscellaneous ----------------

/**
 * @brief Clear the stored ML-DSA key, signature, and message buffers.
 *
 * Resets all module-local state so the next benchmark run does not reuse data
 * from a previous pass.
 *
 * @return None.
 */
void fips204_reset_state(void)
{
    memset(pubkey.data(), 0, pubkey.size());
    memset(seckey.data(), 0, seckey.size());
    memset(signature.data(), 0, signature.size());
    memset(message.data(), 0, message.size());
}

/**
 * @brief Expose the stored ML-DSA public key buffer.
 *
 * @return const uint8_t* Pointer to the module-local public key bytes.
 */
const uint8_t *fips204_get_public_key(void)
{
    return pubkey.data();
}

/**
 * @brief Return the size of the stored ML-DSA public key.
 *
 * @return size_t Public key length in bytes.
 */
size_t fips204_get_public_key_len(void)
{
    return pubkey.size();
}

/**
 * @brief Expose the stored ML-DSA signature buffer.
 *
 * @return const uint8_t* Pointer to the module-local signature bytes.
 */
const uint8_t *fips204_get_signature(void)
{
    return signature.data();
}

/**
 * @brief Return the size of the stored ML-DSA signature.
 *
 * @return size_t Signature length in bytes.
 */
size_t fips204_get_signature_len(void)
{
    return signature.size();
}

/**
 * @brief Expose the stored ML-DSA message buffer.
 *
 * @return const uint8_t* Pointer to the module-local message bytes.
 */
const uint8_t *fips204_get_message(void)
{
    return message.data();
}

/**
 * @brief Return the size of the stored ML-DSA message.
 *
 * @return size_t Message length in bytes.
 */
size_t fips204_get_message_len(void)
{
    return message.size();
}