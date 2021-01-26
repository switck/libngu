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

#ifdef UNIX
# define CHIP_TRNG_SETUP()      
# define CHIP_TRNG_32()       arc4random()
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


STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_random) },

    { MP_ROM_QSTR(MP_QSTR_bytes), MP_ROM_PTR(&random_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_uint32), MP_ROM_PTR(&random_uint32_obj) },
    //{ MP_ROM_QSTR(MP_QSTR_shuffle), MP_ROM_PTR(&random_suffle) },

};

STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_random = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
