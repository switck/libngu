//
// hmac_drbg.h - HMAC_DRBG with SHA-256, from NIST SP 800-90A rev 1, section 10.1.2
//
#pragma once
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t K[32];
    uint8_t V[32];
} hmac_drbg_t;

// Clear secrets (seed material, expiring key state) in a way the optimizer
// cannot elide, unlike a memset() of a local that is about to go out of scope.
static inline void hmac_drbg_wipe(void *p, size_t n)
{
    volatile uint8_t *q = (volatile uint8_t *)p;
    while (n--) {
        *q++ = 0;
    }
}

// Instantiate from seed material: entropy_input || nonce (|| personalization).
// Caller must provide at least 48 bytes of it (256-bit strength + 128-bit nonce).
void hmac_drbg_init(hmac_drbg_t *d, const uint8_t *seed, size_t seed_len);

// Mix additional entropy into the state; never replaces what is already there.
void hmac_drbg_reseed(hmac_drbg_t *d, const uint8_t *entropy, size_t len);

// Fill out with the next len bytes of the stream (backtracking resistant).
void hmac_drbg_generate(hmac_drbg_t *d, uint8_t *out, size_t len);
