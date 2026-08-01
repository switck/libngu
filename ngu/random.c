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

// Yasmarang random number generator
// by Ilya Levin
// http://www.literatecode.com/yasmarang
// Public Domain

// TODO should be marked as confidential memory
static uint32_t yasmarang_pad = 0x0a8ce26f, yasmarang_n = 69, yasmarang_d = 233;
static uint8_t yasmarang_dat = 0;

STATIC uint32_t my_yasmarang(void) {
    yasmarang_pad += yasmarang_dat + yasmarang_d * yasmarang_n;
    yasmarang_pad = (yasmarang_pad << 3) + (yasmarang_pad >> 29);
    yasmarang_n = yasmarang_pad | 2;
    yasmarang_d ^= (yasmarang_pad << 31) + (yasmarang_pad >> 1);
    yasmarang_dat ^= (char)yasmarang_pad ^ (yasmarang_d >> 8) ^ 1;

    return yasmarang_pad ^ (yasmarang_d << 5) ^ (yasmarang_pad >> 18) ^ (yasmarang_dat << 1);
} 

void my_random_bytes(uint8_t *dest, uint32_t count)
{
    uint32_t last = 0;

    while(count) {
        uint32_t chip = CHIP_TRNG_32();

        if(chip == last) {
            // maybe TRNG is not clocked? Fail hard
            mp_raise_OSError(MP_EFAULT);
        }
        last = chip;

        chip ^= my_yasmarang();

        int here = MIN(4, count);

        memcpy(dest, &chip, here);
        dest += here;
        count -= here;
    }
}

STATIC mp_obj_t random_uint32(void) {
    // full 32-bit values, not 30
    CHIP_TRNG_SETUP();

    uint32_t rv = my_yasmarang();

    rv ^= CHIP_TRNG_32();

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
    uint32_t pt = my_yasmarang();
    pt ^= CHIP_TRNG_32();

    while(1) {
        int rv = (int)(pt & mask);
        if(rv < mx) {
            return rv;
        }

        pt ^= my_yasmarang();
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
    // Absorb ALL of the supplied entropy into ALL generator state words.
    //
    // The previous implementation did `yasmarang_pad = int(arg)`, which
    //   (a) kept only the low 32 bits of whatever was passed in, and
    //   (b) never touched yasmarang_n / _d / _dat (left at fixed constants),
    // so after reseeding the entire generator was a pure function of a single
    // 32-bit word -> a 2**32 state space. When the on-chip TRNG is biased or
    // backdoored this reseed is the only independent entropy, so its width is
    // the wallet's real security margin. Feed the full digest, not 4 bytes.
    //
    // Accepts a bytes-like object (preferred) or, for backward compatibility
    // with existing callers/tests, a plain integer.

    uint8_t tmp[4];
    const uint8_t *p;
    size_t len;

    mp_buffer_info_t buf;
    if(mp_get_buffer(arg, &buf, MP_BUFFER_READ)) {
        p = (const uint8_t *)buf.buf;
        len = buf.len;
    } else {
        uint32_t v = mp_obj_get_int_truncated(arg);
        tmp[0] = (uint8_t)(v);
        tmp[1] = (uint8_t)(v >> 8);
        tmp[2] = (uint8_t)(v >> 16);
        tmp[3] = (uint8_t)(v >> 24);
        p = tmp;
        len = sizeof(tmp);
    }

    // Sponge-style absorb: fold each byte across the independent state words
    // (yasmarang_n is re-derived from _pad on every step, so seeding _pad, _d
    // and _dat covers the whole state), stepping the generator between bytes so
    // that early input diffuses into every subsequent output.
    for(size_t i = 0; i < len; i++) {
        yasmarang_pad ^= (uint32_t)p[i] << ((i & 3) * 8);
        yasmarang_d   += (uint32_t)p[i] * 0x01000193u;      // spread across 32 bits
        yasmarang_dat ^= p[i];
        (void)my_yasmarang();
    }

    // Final diffusion rounds so the first bytes fully affect the state.
    for(int i = 0; i < 16; i++) {
        (void)my_yasmarang();
    }

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
