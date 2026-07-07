#ifndef ECDHA_IMPLEMENTATION_H
#define ECDHA_IMPLEMENTATION_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define ECDHA_POINT_TEXT_SIZE 32
#define ECDHA_SHARED_SECRET_TEXT_SIZE 32

typedef struct
{
    uint32_t x;
    uint32_t y;
    bool infinity;
} ecdha_point_t;

typedef struct
{
    uint32_t private_scalar;
    ecdha_point_t public_key;
} ecdha_keypair_t;

typedef struct
{
    uint32_t value;
} ecdha_shared_secret_t;

/**
 * @brief Generate a new ECDH keypair.
 *
 * Produces a private scalar and the corresponding public point.
 *
 * @param [out] keypair Destination keypair structure to populate.
 * @return 0 on success or a negative errno value on failure.
 */
int ecdha_generate_keypair(ecdha_keypair_t *keypair);

/**
 * @brief Serialize a public point into a textual representation.
 *
 * The output is placed into `out` as a NUL-terminated string if the buffer
 * is large enough.
 *
 * @param [in] point Public point to serialize.
 * @param [out] out Destination buffer for text.
 * @param [in] out_size Size of the destination buffer.
 * @return 0 on success or a negative errno value on failure.
 */
int ecdha_public_key_to_string(const ecdha_point_t *point, char *out, size_t out_size);

/**
 * @brief Parse a textual public key representation into a point structure.
 *
 * @param [in] text Textual representation to parse.
 * @param [out] point Destination point structure.
 * @return 0 on success or a negative errno value on parse error.
 */
int ecdha_public_key_from_string(const char *text, ecdha_point_t *point);

/**
 * @brief Compute the shared secret given our keypair and the peer's public key.
 *
 * The result is written into `shared_secret`.
 *
 * @param [in] keypair Our keypair (contains private scalar).
 * @param [in] peer_public_key The peer's public point.
 * @param [out] shared_secret Destination shared-secret structure.
 * @return 0 on success or a negative errno value on failure.
 */
int ecdha_compute_shared_secret(const ecdha_keypair_t *keypair,
                                const ecdha_point_t *peer_public_key,
                                ecdha_shared_secret_t *shared_secret);

/**
 * @brief Convert a shared secret to a textual representation.
 *
 * Writes a NUL-terminated string into `out` when the buffer is large enough.
 *
 * @param [in] shared_secret Shared secret to convert.
 * @param [out] out Destination buffer for textual data.
 * @param [in] out_size Size of the destination buffer.
 * @return 0 on success or negative errno on failure.
 */
int ecdha_shared_secret_to_string(const ecdha_shared_secret_t *shared_secret,
                                  char *out,
                                  size_t out_size);

/**
 * @brief Return the name of the elliptic curve used by this implementation.
 *
 * @return Pointer to a static, NUL-terminated string with the curve name.
 */
const char *ecdha_curve_name(void);

#endif
