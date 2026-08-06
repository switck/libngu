//
// entropy_health_test.c - deterministic entropy repetition checks
//
#include <stdbool.h>
#include <stdio.h>

#include "entropy_health.h"

static int failures;

static void check(bool condition, const char *description)
{
    if (!condition) {
        printf("FAIL: %s\n", description);
        failures++;
    }
}

int main(void)
{
    entropy_health_t health = { 0 };
    entropy_health_t period_three = { 0 };
    entropy_health_t zero = { 0 };

    // Zero policy belongs to the entropy backend wrapper. This helper only
    // checks repetition, so zero is not confused with uninitialized history.
    check(entropy_health_accept(&zero, 0), "first zero is valid history");
    check(!entropy_health_accept(&zero, 0), "repeated zero rejected");

    check(entropy_health_accept(&health, 0x111), "first word accepted");
    check(entropy_health_accept(&health, 0x222), "second distinct word accepted");
    check(!entropy_health_accept(&health, 0x222), "adjacent repeat rejected");
    check(!entropy_health_accept(&health, 0x111), "two-word cycle rejected");
    check(entropy_health_accept(&health, 0x333), "fresh word accepted after rejection");
    check(!entropy_health_accept(&health, 0x222), "rejection does not advance history");

    check(entropy_health_accept(&period_three, 0xaaa), "period-three first word accepted");
    check(entropy_health_accept(&period_three, 0xbbb), "period-three second word accepted");
    check(entropy_health_accept(&period_three, 0xccc), "period-three third word accepted");
    check(entropy_health_accept(&period_three, 0xaaa), "period-three cycle is not detected");

    if (failures) {
        return 1;
    }
    puts("PASS - entropy health");
    return 0;
}
