//
// entropy_health.h - refuse entropy words from a stuck or oscillating source
//
// Pure logic with no dependencies, so the host test suite can drive it
// with deterministic sequences: ngu_tests/entropy_health_test.c
//
#pragma once
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    uint32_t last[2];
} entropy_health_t;

// True if the word is usable: it differs from both previously accepted
// words, so a source stuck on one value or oscillating between two is
// refused. History starts zeroed, which also refuses a first-ever zero
// (STM32 rng_get() returns 0 on peripheral timeout). A refusal does not
// advance the history. Availability cost on a good source: 2^-31
// false-refusal odds per word, about 12% per GiB of output -- immaterial
// at hardware-wallet volumes.
static inline bool entropy_health_ok(entropy_health_t *h, uint32_t word)
{
    if (word == h->last[0] || word == h->last[1]) {
        return false;
    }
    h->last[1] = h->last[0];
    h->last[0] = word;
    return true;
}
