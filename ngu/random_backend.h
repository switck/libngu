//
// random_backend.h - fail-closed target entropy selection
//
#pragma once

#include <stdbool.h>
#include <stdint.h>

#if MICROPY_PY_THREAD && !MICROPY_PY_THREAD_GIL
# error "ngu.random requires the GIL when threads are enabled"
#endif

// Every backend returns false when it cannot provide a word. This lets the
// caller clean sensitive state before raising a MicroPython exception.
#if defined(ESP_PLATFORM)
# if NGU_ESP32_RNG_IS_TRUE_RANDOM != 1
#  error "NGU_ESP32_RNG_IS_TRUE_RANDOM=1 required; see README"
# endif
# include "esp_system.h"
static bool chip_trng_read(uint32_t *out)
{
    *out = esp_random();
    return true;
}

#elif defined(MICROPY_PY_STM)
# if MICROPY_HW_ENABLE_RNG != 1 && NGU_STM32_EXTERNAL_RNG_GET != 1
#  error "MICROPY_HW_ENABLE_RNG=1 or NGU_STM32_EXTERNAL_RNG_GET=1 required"
# endif
// MicroPython's ports/stm32/rng.c returns zero on a peripheral timeout. An
// external provider uses the same interface, so reject zero for both paths.
extern uint32_t rng_get(void);
static bool chip_trng_read(uint32_t *out)
{
    uint32_t word = rng_get();
    if(!word) {
        return false;
    }
    *out = word;
    return true;
}

#elif defined(__APPLE__) || defined(__FreeBSD__)
# include <stdlib.h>
static bool chip_trng_read(uint32_t *out)
{
    *out = arc4random();
    return true;
}

#elif defined(__linux__)
# include <sys/random.h>
static bool chip_trng_read(uint32_t *out)
{
    return getrandom(out, sizeof(*out), 0) == (ssize_t)sizeof(*out);
}

#else
# error "No hardware or OS entropy source is defined for this target"
#endif
