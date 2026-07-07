#include "ECDHA_implementation.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/kernel.h>

static const uint32_t curve_p = 9739U;
static const uint32_t curve_a = 497U;
static const uint32_t curve_b = 1768U;
static const ecdha_point_t curve_base_point =
{
        .x = 1804U,
        .y = 5368U,
        .infinity = false,
};

static uint32_t mod_add(uint32_t lhs, uint32_t rhs)
{
    return (uint32_t)(((uint64_t) lhs + (uint64_t) rhs) % curve_p);
}

static uint32_t mod_sub(uint32_t lhs, uint32_t rhs)
{
    return (uint32_t)(((uint64_t) lhs + curve_p - (rhs % curve_p)) % curve_p);
}

static uint32_t mod_mul(uint32_t lhs, uint32_t rhs)
{
    return (uint32_t)(((uint64_t) lhs * (uint64_t) rhs) % curve_p);
}

static int32_t mod_inverse(int32_t value)
{
    int32_t t = 0;
    int32_t new_t = 1;
    int32_t r = (int32_t) curve_p;
    int32_t new_r = value % (int32_t) curve_p;

    if (new_r < 0)
    {
        new_r += (int32_t) curve_p;
    }

    while (new_r != 0)
    {
        int32_t quotient = r / new_r;
        int32_t temp_t = t - quotient * new_t;
        int32_t temp_r = r - quotient * new_r;

        t = new_t;
        new_t = temp_t;
        r = new_r;
        new_r = temp_r;
    }

    if (r > 1)
    {
        return -1;
    }

    if (t < 0)
    {
        t += (int32_t) curve_p;
    }

    return t;
}

static bool point_is_infinity(const ecdha_point_t *point)
{
    return point == NULL || point->infinity;
}

static bool point_is_on_curve(const ecdha_point_t *point)
{
    uint32_t lhs;
    uint32_t rhs;

    if (point == NULL || point->infinity)
    {
        return false;
    }

    lhs = mod_mul(point->y, point->y);
    rhs = mod_add(mod_add(mod_mul(mod_mul(point->x, point->x), point->x), mod_mul(curve_a, point->x)), curve_b);

    return lhs == rhs;
}

static ecdha_point_t point_add(const ecdha_point_t *lhs, const ecdha_point_t *rhs)
{
    ecdha_point_t result = {
            .x = 0U,
            .y = 0U,
            .infinity = true,
    };

    if (point_is_infinity(lhs))
    {
        return *rhs;
    }

    if (point_is_infinity(rhs))
    {
        return *lhs;
    }

    if (lhs->x == rhs->x && lhs->y != rhs->y)
    {
        return result;
    }

    if (lhs->x == rhs->x && lhs->y == rhs->y)
    {
        if (lhs->y == 0U)
        {
            return result;
        }

        uint32_t numerator = mod_add(mod_mul(3U, mod_mul(lhs->x, lhs->x)), curve_a);
        int32_t inverse = mod_inverse((int32_t) mod_mul(2U, lhs->y));

        if (inverse < 0)
        {
            return result;
        }

        uint32_t slope = mod_mul(numerator, (uint32_t) inverse);
        uint32_t x3 = mod_sub(mod_sub(mod_mul(slope, slope), lhs->x), rhs->x);
        uint32_t y3 = mod_sub(mod_mul(slope, mod_sub(lhs->x, x3)), lhs->y);

        result.x = x3;
        result.y = y3;
        result.infinity = false;
        return result;
    }

    {
        uint32_t numerator = mod_sub(rhs->y, lhs->y);
        int32_t inverse = mod_inverse((int32_t) mod_sub(rhs->x, lhs->x));

        if (inverse < 0)
        {
            return result;
        }

        uint32_t slope = mod_mul(numerator, (uint32_t) inverse);
        uint32_t x3 = mod_sub(mod_sub(mod_mul(slope, slope), lhs->x), rhs->x);
        uint32_t y3 = mod_sub(mod_mul(slope, mod_sub(lhs->x, x3)), lhs->y);

        result.x = x3;
        result.y = y3;
        result.infinity = false;
        return result;
    }
}

static ecdha_point_t point_scalar_mul(uint32_t scalar, const ecdha_point_t *point)
{
    ecdha_point_t result = {
            .x = 0U,
            .y = 0U,
            .infinity = true,
    };
    ecdha_point_t addend = *point;

    while (scalar != 0U)
    {
        if ((scalar & 1U) != 0U)
        {
            result = point_add(&result, &addend);
        }

        addend = point_add(&addend, &addend);
        scalar >>= 1U;
    }

    return result;
}

static uint32_t mix_seed(uint32_t seed)
{
    seed ^= seed << 13U;
    seed ^= seed >> 17U;
    seed ^= seed << 5U;
    return seed;
}

const char *ecdha_curve_name(void)
{
    return "toy-ecdh-y2=x3+497x+1768(mod9739)";
}

int ecdha_generate_keypair(ecdha_keypair_t *keypair)
{
    uint32_t seed;
    uint32_t scalar;

    if (keypair == NULL)
    {
        return -EINVAL;
    }

    seed = (uint32_t) k_uptime_get_32();
    seed ^= k_cycle_get_32();
    seed = mix_seed(seed ^ 0xA5A5A5A5U);
    scalar = (seed % 4094U) + 2U;

    for (int attempt = 0; attempt < 32; attempt++)
    {
        keypair->private_scalar = scalar;
        keypair->public_key = point_scalar_mul(scalar, &curve_base_point);

        if (!point_is_infinity(&keypair->public_key))
        {
            return 0;
        }

        scalar = ((scalar + 1U) % 4094U) + 2U;
    }

    return -EIO;
}

int ecdha_public_key_to_string(const ecdha_point_t *point, char *out, size_t out_size)
{
    if (point == NULL || out == NULL || out_size == 0U)
    {
        return -EINVAL;
    }

    if (point->infinity)
    {
        return snprintf(out, out_size, "INF") < 0 ? -EIO : 0;
    }

    if (snprintf(out, out_size, "%lu,%lu",
            (unsigned long) point->x,
            (unsigned long) point->y) >= (int) out_size)
    {
        return -ENOSPC;
    }

    return 0;
}

int ecdha_public_key_from_string(const char *text, ecdha_point_t *point)
{
    unsigned long x;
    unsigned long y;

    if (text == NULL || point == NULL)
    {
        return -EINVAL;
    }

    if (strcmp(text, "INF") == 0)
    {
        point->x = 0U;
        point->y = 0U;
        point->infinity = true;
        return 0;
    }

    if (sscanf(text, "%lu,%lu", &x, &y) != 2)
    {
        return -EINVAL;
    }

    point->x = (uint32_t) x;
    point->y = (uint32_t) y;
    point->infinity = false;

    if (!point_is_on_curve(point))
    {
        return -EINVAL;
    }

    return 0;
}

int ecdha_compute_shared_secret(const ecdha_keypair_t *keypair,
                                const ecdha_point_t *peer_public_key,
                                ecdha_shared_secret_t *shared_secret)
{
    ecdha_point_t secret_point;

    if (keypair == NULL || peer_public_key == NULL || shared_secret == NULL)
    {
        return -EINVAL;
    }

    if (!point_is_on_curve(peer_public_key))
    {
        return -EINVAL;
    }

    secret_point = point_scalar_mul(keypair->private_scalar, peer_public_key);
    if (point_is_infinity(&secret_point))
    {
        return -EIO;
    }

    shared_secret->value = secret_point.x;
    return 0;
}

int ecdha_shared_secret_to_string(const ecdha_shared_secret_t *shared_secret,
                                  char *out,
                                  size_t out_size)
{
    if (shared_secret == NULL || out == NULL || out_size == 0U)
    {
        return -EINVAL;
    }

    if (snprintf(out, out_size, "%lu", (unsigned long) shared_secret->value) >= (int) out_size)
    {
        return -ENOSPC;
    }

    return 0;
}
