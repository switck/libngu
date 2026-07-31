//
// entropy_health_test.c - deterministic tests of the entropy health rule
//
// Build and run on the host: make health    (part of "make tests")
//
#include <stdio.h>
#include "entropy_health.h"

static int fails;

static void check(bool got, bool want, const char *what)
{
    if (got != want) {
        printf("FAIL: %s\n", what);
        fails++;
    }
}

int main(void)
{
    entropy_health_t h = { { 0 } };

    // history starts zeroed: a first-ever zero (STM32 rng_get() timeout)
    // must be refused
    check(entropy_health_ok(&h, 0), false, "first-ever zero refused");

    // distinct words pass
    check(entropy_health_ok(&h, 0x111), true, "fresh word accepted");
    check(entropy_health_ok(&h, 0x222), true, "second fresh word accepted");

    // stuck source: immediate repeat refused
    check(entropy_health_ok(&h, 0x222), false, "stuck source refused");

    // oscillating source: A,B,A refused
    check(entropy_health_ok(&h, 0x111), false, "period-2 oscillation refused");

    // a refusal must not advance history: fresh words still judged
    // against the last two *accepted* words
    check(entropy_health_ok(&h, 0x333), true, "recovers after refusal");
    check(entropy_health_ok(&h, 0x222), false, "refusal did not launder history");

    // documented limitation: period-3 repetition passes (raw-source
    // statistical validation is the integrator's job, see README)
    entropy_health_t h3 = { { 0 } };
    check(entropy_health_ok(&h3, 0xa), true, "p3 word 1");
    check(entropy_health_ok(&h3, 0xb), true, "p3 word 2");
    check(entropy_health_ok(&h3, 0xc), true, "p3 word 3");
    check(entropy_health_ok(&h3, 0xa), true, "period-3 passes (documented)");

    if (fails) {
        printf("FAIL - entropy health: %d\n", fails);
        return 1;
    }
    printf("PASS - entropy health\n");
    return 0;
}
