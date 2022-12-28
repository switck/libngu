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
#include "bech32/segwit_addr.h"

#include "base32.h"
#include "hash.h"
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

    return mp_obj_new_str((char *)tmp, len_out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(c_b32encode_obj, c_b32encode);

// 
// Base 58 - always with checksum, never with a particular prefix
// 

// for libbase58 to call
bool b58_sha256_impl(void *out, const void *inp, int len)
{
    sha256_single(inp, len, out);

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

    return mp_obj_new_str(tmp, len_out-1);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(c_b58encode_obj, c_b58encode);

// Segwit = BECH32(m)

STATIC mp_obj_t c_segwit_encode(mp_obj_t hrp_in, mp_obj_t witver_in, mp_obj_t prog_in)
{
    const char *hrp = mp_obj_str_get_str(hrp_in);
    int witver = mp_obj_get_int_truncated(witver_in);

    mp_buffer_info_t prog;
    mp_get_buffer_raise(prog_in, &prog, MP_BUFFER_READ);


    char tmp[127];

    int ok = segwit_addr_encode(tmp, hrp, witver, prog.buf, prog.len);
    if(!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("segwit_addr_encode"));
    }

    return mp_obj_new_str(tmp, strlen(tmp));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(c_segwit_encode_obj, c_segwit_encode);


STATIC mp_obj_t c_segwit_decode(mp_obj_t addr_in)
{
    const char *addr = mp_obj_str_get_str(addr_in);

    char hrp_actual[20];
    uint8_t data[84];
    size_t data_len = sizeof(data);
    int version = -1;

    int ok = segwit_addr_decode_detailed(&version, data, &data_len, hrp_actual, addr);
    if(!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("bech32 encoding"));
    }

    mp_obj_t    rv[3] = {
        mp_obj_new_str(hrp_actual, strlen(hrp_actual)),
        MP_OBJ_NEW_SMALL_INT(version),
        mp_obj_new_bytes(data, data_len),
    };

    return mp_obj_new_tuple(3, rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(c_segwit_decode_obj, c_segwit_decode);

// BECH32

STATIC mp_obj_t c_nip19_encode(mp_obj_t hrp_in, mp_obj_t prog_in)
{
    const char *hrp = mp_obj_str_get_str(hrp_in);

    mp_buffer_info_t prog;
    mp_get_buffer_raise(prog_in, &prog, MP_BUFFER_READ);
    if (prog.len != 32) {
    	mp_raise_ValueError(MP_ERROR_TEXT("key must be 32 bytes"));
    }
	bech32_encoding enc = BECH32_ENCODING_BECH32;

    uint8_t data[65];
    size_t datalen = 0;
	convert_bits(data, &datalen, 5, prog.buf, prog.len, 8, 1);

	char tmp[127];
    int ok = bech32_encode(tmp, hrp, data, datalen, enc);
    if(!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("nip19_encode"));
    }

    return mp_obj_new_str(tmp, strlen(tmp));
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(c_nip19_encode_obj, c_nip19_encode);


STATIC mp_obj_t c_nip19_decode(mp_obj_t str_in)
{
    const char *str = mp_obj_str_get_str(str_in);

    uint8_t data[84];
    char hrp_actual[84];
    size_t data_len;

    bech32_encoding enc = bech32_decode(hrp_actual, data, &data_len, str);
    if (enc == BECH32_ENCODING_NONE) {
    	mp_raise_ValueError(MP_ERROR_TEXT("nip19_decode"));
    }
    if (enc == BECH32_ENCODING_BECH32M) {
    	mp_raise_ValueError(MP_ERROR_TEXT("must be bech32 encoding not bech32m"));
    }
    uint8_t res[65];
    size_t reslen = 0;
    convert_bits(res, &reslen, 8, data, data_len, 5, 0);
    return mp_obj_new_bytes(res, reslen);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(c_nip19_decode_obj, c_nip19_decode);


STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_codecs) },

    { MP_ROM_QSTR(MP_QSTR_b32_encode), MP_ROM_PTR(&c_b32encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_b32_decode), MP_ROM_PTR(&c_b32decode_obj) },

    { MP_ROM_QSTR(MP_QSTR_b58_encode), MP_ROM_PTR(&c_b58encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_b58_decode), MP_ROM_PTR(&c_b58decode_obj) },

    { MP_ROM_QSTR(MP_QSTR_segwit_encode), MP_ROM_PTR(&c_segwit_encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_segwit_decode), MP_ROM_PTR(&c_segwit_decode_obj) },

    { MP_ROM_QSTR(MP_QSTR_nip19_encode), MP_ROM_PTR(&c_nip19_encode_obj) },
    { MP_ROM_QSTR(MP_QSTR_nip19_decode), MP_ROM_PTR(&c_nip19_decode_obj) },
};

STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_codecs = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
