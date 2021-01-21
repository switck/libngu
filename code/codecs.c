// 
// codecs - missing codecs: b32, b58
//
// - "short" strings only
//
#include "py/runtime.h"
#include "py/mperrno.h"
#include <string.h>
#include <stdio.h>
#include "my_assert.h"

#if MICROPY_SSL_MBEDTLS
# include "mbedtls/sha256.h"
#else
# error "need sha256"
#endif

#include "base32.h"

#include "libbase58.h"

// 
// Base 32
// 
STATIC mp_obj_t c_b32decode(mp_obj_t arg_in)
{
    const char *arg = mp_obj_str_get_str(arg_in);
    uint8_t tmp[strlen(arg)+10];

    int len_out = base32_decode((uint8_t *)arg, tmp, sizeof(tmp));
    if(len_out < 0) {
        mp_raise_ValueError(NULL);
    }

    return mp_obj_new_bytes(tmp, len_out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(c_b32decode_obj, c_b32decode);


STATIC mp_obj_t c_b32encode(mp_obj_t arg_in) {
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg_in, &buf, MP_BUFFER_READ);

    uint8_t tmp[(buf.len*2) + 20];

    int len_out = base32_encode(buf.buf, buf.len, tmp, sizeof(tmp));
    if(len_out < 0) {
        mp_raise_ValueError(NULL);
    }

    return mp_obj_new_bytes(tmp, len_out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(c_b32encode_obj, c_b32encode);

// 
// Base 58 - always with checksum, never with a particular prefix
// 

// for libbase58 to call
bool b58_sha256_impl(void *out, const void *inp, size_t len)
{
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, inp, len);
    mbedtls_sha256_finish_ret(&ctx, out);

    return true;
}

STATIC mp_obj_t c_b58decode(mp_obj_t arg_in)
{
    uint8_t tmp[128];

    int len_out = base58_decode_check(mp_obj_str_get_str(arg_in), tmp, sizeof(tmp));
    if(len_out <= 0) {
        mp_raise_ValueError(NULL);
    }

    return mp_obj_new_bytes(tmp, len_out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(c_b58decode_obj, c_b58decode);


STATIC mp_obj_t c_b58encode(mp_obj_t arg_in)
{
    mp_buffer_info_t buf;
    mp_get_buffer_raise(arg_in, &buf, MP_BUFFER_READ);

    char tmp[128];

    int len_out = base58_encode_check(buf.buf, buf.len, tmp, sizeof(tmp));
    if(len_out <= 0) {
        mp_raise_ValueError(NULL);
    }

    return mp_obj_new_bytes((uint8_t *)tmp, len_out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(c_b58encode_obj, c_b58encode);



STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_codecs) },

    { MP_ROM_QSTR(MP_QSTR_b32encode), MP_ROM_PTR(&c_b32encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_b32decode), MP_ROM_PTR(&c_b32decode_obj) },

    { MP_ROM_QSTR(MP_QSTR_b58encode), MP_ROM_PTR(&c_b58encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_b58decode), MP_ROM_PTR(&c_b58decode_obj) },

};

STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_codecs = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
