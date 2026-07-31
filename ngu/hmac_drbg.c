//
// hmac_drbg.c - HMAC_DRBG with SHA-256, from NIST SP 800-90A rev 1, section 10.1.2
//
// Deliberately minimal: no prediction resistance, no additional input on
// generate, and no reseed-interval counter -- callers are expected to mix in
// fresh entropy via hmac_drbg_reseed() (see random.c, which also XORs raw
// TRNG words over every output). Verified against official NIST CAVP vectors
// by ngu_tests/hmac_drbg_cavp.c; run with "make cavp" in ngu_tests.
//
// Uses whichever SHA-256 the rest of libngu is built with (see hash.c).
// HMAC itself is done here: both backends' HMAC layers were avoided because
// mbedtls' allocates memory, and a DRBG must not have a failure path.
//
#include "hmac_drbg.h"
#include <string.h>

// Take the SHA-256 backend choice from the port's config, exactly as hash.c
// does. Only the host-compiled CAVP test harness has no MicroPython tree; it
// opts out and selects the backend with -D flags instead.
#ifndef NGU_HMAC_DRBG_NO_MPCONFIG
# include "py/mpconfig.h"
#endif

#if MICROPY_SSL_MBEDTLS
# include "mbedtls/sha256.h"

// Return values below are discarded, which is sound only because the
// software SHA-256 cannot fail. Hardware replacements can, so refuse them
// until a target proves and handles that (ESP-IDF enables one by default).
# if defined(MBEDTLS_SHA256_ALT)
#  error "MBEDTLS_SHA256_ALT can fail at runtime; this DRBG has no failure path."
# endif

typedef mbedtls_sha256_context sha256_ctx_t;
# define sha256_begin(c)        do { mbedtls_sha256_init(c); \
                                     mbedtls_sha256_starts_ret(c, 0); } while(0)
# define sha256_add(c, p, n)    mbedtls_sha256_update_ret(c, p, n)
# define sha256_end(c, out)     do { mbedtls_sha256_finish_ret(c, out); \
                                     mbedtls_sha256_free(c); } while(0)
#else
# include "cifra/sha2.h"

typedef cf_sha256_context sha256_ctx_t;
# define sha256_begin(c)        cf_sha256_init(c)
# define sha256_add(c, p, n)    cf_sha256_update(c, p, n)
# define sha256_end(c, out)     cf_sha256_digest_final(c, out)
#endif

// HMAC-SHA256, incremental, for the fixed 32-byte keys this DRBG uses.
typedef struct {
    sha256_ctx_t    hash;
    uint8_t         key[32];
} hmac_ctx_t;

static void hmac_start(hmac_ctx_t *h, const uint8_t key[32])
{
    uint8_t pad[64];

    memcpy(h->key, key, 32);
    for (int i = 0; i < 64; i++) {
        pad[i] = 0x36 ^ (i < 32 ? key[i] : 0);
    }
    sha256_begin(&h->hash);
    sha256_add(&h->hash, pad, 64);

    hmac_drbg_wipe(pad, sizeof(pad));
}

static void hmac_add(hmac_ctx_t *h, const uint8_t *data, size_t len)
{
    sha256_add(&h->hash, data, len);
}

static void hmac_done(hmac_ctx_t *h, uint8_t out[32])
{
    uint8_t pad[64], inner[32];

    sha256_end(&h->hash, inner);

    for (int i = 0; i < 64; i++) {
        pad[i] = 0x5c ^ (i < 32 ? h->key[i] : 0);
    }
    sha256_begin(&h->hash);
    sha256_add(&h->hash, pad, 64);
    sha256_add(&h->hash, inner, 32);
    sha256_end(&h->hash, out);

    hmac_drbg_wipe(pad, sizeof(pad));
    hmac_drbg_wipe(inner, sizeof(inner));
    hmac_drbg_wipe(h->key, sizeof(h->key));
}

// HMAC_DRBG_Update (section 10.1.2.2)
static void drbg_update(hmac_drbg_t *d, const uint8_t *data, size_t len)
{
    int rounds = len ? 2 : 1;

    for (uint8_t r = 0; r < rounds; r++) {
        hmac_ctx_t h;

        // K = HMAC(K, V || r || data)
        hmac_start(&h, d->K);
        hmac_add(&h, d->V, 32);
        hmac_add(&h, &r, 1);
        if (len) {
            hmac_add(&h, data, len);
        }
        hmac_done(&h, d->K);

        // V = HMAC(K, V)
        hmac_start(&h, d->K);
        hmac_add(&h, d->V, 32);
        hmac_done(&h, d->V);
    }
}

// HMAC_DRBG_Instantiate_algorithm (section 10.1.2.3)
void hmac_drbg_init(hmac_drbg_t *d, const uint8_t *seed, size_t seed_len)
{
    memset(d->K, 0x00, 32);
    memset(d->V, 0x01, 32);
    drbg_update(d, seed, seed_len);
}

// HMAC_DRBG_Reseed_algorithm (section 10.1.2.4)
void hmac_drbg_reseed(hmac_drbg_t *d, const uint8_t *entropy, size_t len)
{
    drbg_update(d, entropy, len);
}

// HMAC_DRBG_Generate_algorithm (section 10.1.2.5), additional input = Null
void hmac_drbg_generate(hmac_drbg_t *d, uint8_t *out, size_t len)
{
    while (len) {
        hmac_ctx_t h;
        size_t here = (len < 32) ? len : 32;

        // V = HMAC(K, V)
        hmac_start(&h, d->K);
        hmac_add(&h, d->V, 32);
        hmac_done(&h, d->V);

        memcpy(out, d->V, here);
        out += here;
        len -= here;
    }

    drbg_update(d, NULL, 0);
}
