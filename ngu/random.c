//
// random - cryptographic random number generation
//
// - all output comes from an HMAC_DRBG (SP 800-90A, SHA-256) which is seeded
//   from the chip/OS entropy source on first use; see hmac_drbg.c
// - reseed() mixes caller-provided entropy (secure elements, dice rolls...)
//   into the DRBG state; it never replaces entropy already accumulated
// - every output word is also XORed with a fresh word from the entropy
//   source, so output stays unpredictable even if one side is weak
// - an entropy source that gets stuck on one value (unclocked TRNG,
//   persistent STM32 timeout-zero) or oscillates between two (dying ring
//   oscillator) faults hard (OSError), even across calls
// - calls must be serialized: by having no threads, or by the VM's GIL;
//   direct C callers outside the VM own that serialization themselves
//
#include "py/runtime.h"
#include "py/mperrno.h"
#include <string.h>
#include "my_assert.h"
#include "hmac_drbg.h"
#include "entropy_health.h"

#if MICROPY_PY_THREAD && !MICROPY_PY_THREAD_GIL
# error "ngu.random keeps unsynchronized state; threads need the GIL enabled."
#endif

//
// Entropy source selection. Fail-closed: unknown targets do not build,
// and there is no software fallback of any kind. See README for what an
// integrator must guarantee about each source.
//
// Attestations are checked by value, not existence: an undefined macro
// evaluates to 0 here, so absent, zero, and wrong values all fail alike.
// Every backend has the same contract: chip_trng_read() fills one word or
// says it could not.
#if defined(ESP_PLATFORM)
# if NGU_ESP32_RNG_IS_TRUE_RANDOM != 1
#  error "Attest with NGU_ESP32_RNG_IS_TRUE_RANDOM=1 that esp_random() has a \
true entropy source (RF or bootloader source enabled) before the first RNG \
call on your chip and boot sequence; otherwise its output is pseudo-random."
# endif
# include "esp_system.h"
static bool chip_trng_read(uint32_t *out)
{
    *out = esp_random();
    return true;
}

#elif MICROPY_PY_STM
# if NGU_STM32_RNG_GET_IS_HARDWARE != 1
#  error "Attest with NGU_STM32_RNG_GET_IS_HARDWARE=1 that the rng_get() you \
link reads the MCU's TRNG peripheral. Careful: when MICROPY_HW_ENABLE_RNG is \
0, upstream MicroPython silently provides a PSEUDO-random rng_get()."
# endif
// ports/stm32/rng.c, or the board's replacement for it. Its API conflates
// a peripheral timeout (returns 0) with a valid zero word, so treat every
// zero as a failed read; a good TRNG loses one word in 2^32.
extern uint32_t rng_get(void);
static bool chip_trng_read(uint32_t *out)
{
    uint32_t w = rng_get();
    if (w == 0) {
        return false;
    }
    *out = w;
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
# include <unistd.h>
static bool chip_trng_read(uint32_t *out)
{
    return getentropy(out, sizeof(uint32_t)) == 0;
}

#else
# error "No entropy source known for this target. Add one here; hardware or OS entropy only."
#endif

static hmac_drbg_t drbg;
static bool drbg_seeded;

// One usable word from the entropy source, or false: backend failure and
// the health rule (stuck or oscillating source; see entropy_health.h) both
// land here, so callers have a single wipe-then-raise error boundary.
static bool trng_word_ok(uint32_t *out)
{
    static entropy_health_t health;
    uint32_t rv;

    if (!chip_trng_read(&rv) || !entropy_health_ok(&health, rv)) {
        return false;
    }

    *out = rv;
    return true;
}

static uint32_t trng_word(void)
{
    uint32_t rv;
    if (!trng_word_ok(&rv)) {
        mp_raise_OSError(MP_EFAULT);
    }
    return rv;
}

// First use: seed the DRBG with 64 bytes of raw entropy. The SP 800-90A
// minimum is 48 (256-bit strength + 128-bit nonce); the extra 16 bytes are
// margin for a mildly biased source. No output can derive from constants.
static void ensure_seeded(void)
{
    if (drbg_seeded) return;

    uint32_t seed[16];
    for (int i = 0; i < 16; i++) {
        if (!trng_word_ok(&seed[i])) {
            // wipe the words already collected, then fault
            hmac_drbg_wipe(seed, sizeof(seed));
            mp_raise_OSError(MP_EFAULT);
        }
    }
    hmac_drbg_init(&drbg, (const uint8_t *)seed, sizeof(seed));
    hmac_drbg_wipe(seed, sizeof(seed));

    drbg_seeded = true;
}

void my_random_bytes(uint8_t *dest, uint32_t count)
{
    ensure_seeded();
    hmac_drbg_generate(&drbg, dest, count);

    // XOR fresh entropy over the DRBG stream.
    while (count) {
        uint32_t chip = trng_word();

        int here = MIN(4, count);
        for (int i = 0; i < here; i++) {
            dest[i] ^= (chip >> (i * 8)) & 0xff;
        }
        dest += here;
        count -= here;
    }
}

STATIC mp_obj_t random_uint32(void) {
    // full 32-bit values, not 30
    uint32_t rv;
    my_random_bytes((uint8_t *)&rv, 4);

    return mp_obj_new_int_from_uint(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(random_uint32_obj, random_uint32);

int _bit_length(uint32_t x)
{
    if(!x) return 0;

    int bits = 1;
    while(x >> bits) {
        bits += 1;
    }
    return bits;
}

int _rand_below(int mx)
{
    if(mx <= 1) return 0;

    int bl = _bit_length(mx);
    assert(bl && (bl < 31));

    uint32_t mask = (1u << bl) - 1;

    while(1) {
        uint32_t pt;
        my_random_bytes((uint8_t *)&pt, 4);

        int rv = (int)(pt & mask);
        if(rv < mx) {
            return rv;
        }
    }
}

STATIC mp_obj_t random_uniform(mp_obj_t mx_in) {
    int mx = mp_obj_get_int_truncated(mx_in);

    return mp_obj_new_int_from_uint(_rand_below(mx));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(random_uniform_obj, random_uniform);


STATIC mp_obj_t random_bytes(mp_obj_t count_in)
{
    int count = mp_obj_get_int_truncated(count_in);
    if(count < 0 || count > 4096) {
        mp_raise_ValueError(MP_ERROR_TEXT("out of range"));
    }

    vstr_t rv;
    vstr_init_len(&rv, count);

    my_random_bytes((uint8_t *)rv.buf, count);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(random_bytes_obj, random_bytes);


// Mix caller-provided entropy into the DRBG state. Takes any bytes-like
// object; entropy from multiple sources composes. An int is accepted for
// back-compat, but carries at most 32 bits -- pass bytes instead.
STATIC mp_obj_t random_reseed(mp_obj_t arg)
{
    mp_buffer_info_t inp;
    uint8_t legacy[4];

    if(!mp_get_buffer(arg, &inp, MP_BUFFER_READ)) {
        uint32_t v = mp_obj_get_int_truncated(arg);
        legacy[0] = v; legacy[1] = v >> 8; legacy[2] = v >> 16; legacy[3] = v >> 24;
        inp.buf = legacy;
        inp.len = sizeof(legacy);
    }
    if(inp.len == 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("empty"));
    }

    ensure_seeded();
    hmac_drbg_reseed(&drbg, inp.buf, inp.len);

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(random_reseed_obj, random_reseed);


STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_random) },

    { MP_ROM_QSTR(MP_QSTR_bytes), MP_ROM_PTR(&random_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_uint32), MP_ROM_PTR(&random_uint32_obj) },
    { MP_ROM_QSTR(MP_QSTR_uniform), MP_ROM_PTR(&random_uniform_obj) },
    { MP_ROM_QSTR(MP_QSTR_reseed), MP_ROM_PTR(&random_reseed_obj) },
};

STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_random = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
