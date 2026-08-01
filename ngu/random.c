// 
// random - RNG stuff
//
// - common interface to TRNG specific to your chip
// - whitening
// - pick new privkeys
//
#include "py/runtime.h"
#include "py/mperrno.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "my_assert.h"
#include "cifra/drbg.h"

// ESP32 code
#ifdef ESP_PLATFORM
# include "esp_system.h"
# define CHIP_TRNG_SETUP()      
# define CHIP_TRNG_32()         esp_random()
#endif

#ifdef MICROPY_PY_STM
// ports/stm32/rng.c
extern uint32_t rng_get(void);
# define CHIP_TRNG_SETUP()      
# define CHIP_TRNG_32()         rng_get()

# ifndef MICROPY_HW_ENABLE_RNG
# error "get a HW TRNG plz"
# endif
#endif

#if defined(__APPLE__) || defined(__FreeBSD__)
# define CHIP_TRNG_SETUP()      
# define CHIP_TRNG_32()         arc4random()
#endif

#ifdef __linux__
# define CHIP_TRNG_SETUP()
# define CHIP_TRNG_32()         random()
#endif

#ifndef CHIP_TRNG_SETUP
# error "need chip TRNG function"
# define CHIP_TRNG_SETUP()
# define CHIP_TRNG_32()         0x5a5a5a5a
#endif

static cf_hash_drbg_sha256 drbg;
static bool drbg_ready;

STATIC void drbg_setup(const void *seed, size_t seed_len)
{
    if(drbg_ready) {
        cf_hash_drbg_sha256_reseed(&drbg, seed, seed_len, NULL, 0);
        return;
    }

    CHIP_TRNG_SETUP();

    uint32_t entropy[8];
    for(int i = 0; i < 8; i++) {
        entropy[i] = CHIP_TRNG_32();
    }

    static const char domain[] = "libngu.random";
    cf_hash_drbg_sha256_init(&drbg, entropy, sizeof(entropy),
                             NULL, 0, domain, sizeof(domain)-1);
    memset(entropy, 0, sizeof(entropy));
    drbg_ready = true;

    if(seed_len) {
        cf_hash_drbg_sha256_reseed(&drbg, seed, seed_len, NULL, 0);
    }
}

void my_random_bytes(uint8_t *dest, uint32_t count)
{
    if(!drbg_ready) {
        drbg_setup(NULL, 0);
    }
    cf_hash_drbg_sha256_gen(&drbg, dest, count);

    uint32_t last = 0;

    while(count) {
        uint32_t chip = CHIP_TRNG_32();

        if(chip == last) {
            // maybe TRNG is not clocked? Fail hard
            mp_raise_OSError(MP_EFAULT);
        }
        last = chip;

        int here = MIN(4, count);
        for(int i = 0; i < here; i++) {
            dest[i] ^= ((uint8_t *)&chip)[i];
        }
        dest += here;
        count -= here;
    }
}

STATIC mp_obj_t random_uint32(void) {
    // full 32-bit values, not 30
    CHIP_TRNG_SETUP();

    uint32_t rv;
    my_random_bytes((uint8_t *)&rv, sizeof(rv));

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

    CHIP_TRNG_SETUP();

    uint32_t mask = (2 << bl)-1;

    while(1) {
        uint32_t pt;
        my_random_bytes((uint8_t *)&pt, sizeof(pt));
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
    if(count > 4096) {
        mp_raise_ValueError(MP_ERROR_TEXT("too many"));
    }

    vstr_t rv;
    vstr_init_len(&rv, count);

    my_random_bytes((uint8_t *)rv.buf, count);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(random_bytes_obj, random_bytes);


STATIC mp_obj_t random_reseed(mp_obj_t arg)
{
    mp_buffer_info_t seed;
    mp_get_buffer_raise(arg, &seed, MP_BUFFER_READ);
    if(seed.len < 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("seed too short"));
    }

    drbg_setup(seed.buf, seed.len);

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
