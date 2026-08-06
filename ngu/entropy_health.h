//
// entropy_health.h - detect exact repetition in recent entropy words
//
#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct {
    uint32_t history[2];
    uint8_t count;
} entropy_health_t;

// Reject a word matching either of the previous two accepted words. This
// catches a stuck source and exact two-word cycles. Rejections do not advance
// history. This is a narrow runtime check, not entropy-source validation.
static inline bool entropy_health_accept(entropy_health_t *health, uint32_t word)
{
    for (uint8_t i = 0; i < health->count; i++) {
        if (word == health->history[i]) {
            return false;
        }
    }

    health->history[1] = health->history[0];
    health->history[0] = word;
    if (health->count < 2) {
        health->count++;
    }
    return true;
}
