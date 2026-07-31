//
// hmac_drbg_cavp.c - verify ngu/hmac_drbg.c against official NIST CAVP vectors
//
// Build and run on the host: make cavp    (part of "make tests")
// Vectors: hmac_drbg_cavp_vectors.h, extracted by gen_hmac_drbg_vectors.py
// from NIST's drbgtestvectors.zip. Each vector is: instantiate, optional
// reseed, generate twice; the second generate output must match ReturnedBits.
//
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "hmac_drbg.h"
#include "hmac_drbg_cavp_vectors.h"

int main(void)
{
    const int num = sizeof(CAVP_VECTORS) / sizeof(CAVP_VECTORS[0]);
    int fails = 0;

    for (int i = 0; i < num; i++) {
        const cavp_vector_t *v = &CAVP_VECTORS[i];
        hmac_drbg_t d;
        uint8_t got[256];

        assert(v->expect_len <= sizeof(got));

        hmac_drbg_init(&d, v->seed, v->seed_len);
        if (v->reseed) {
            hmac_drbg_reseed(&d, v->reseed, v->reseed_len);
        }
        hmac_drbg_generate(&d, got, v->expect_len);     // discarded, per CAVP
        hmac_drbg_generate(&d, got, v->expect_len);

        if (memcmp(got, v->expect, v->expect_len) != 0) {
            printf("FAIL: %s\n", v->file);
            fails++;
        }
    }

    if (fails) {
        printf("FAIL - hmac_drbg CAVP: %d of %d vectors\n", fails, num);
        return 1;
    }
    printf("PASS - hmac_drbg CAVP (%d vectors)\n", num);
    return 0;
}
