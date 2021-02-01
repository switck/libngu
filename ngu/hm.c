//
// hm.c - HMAC, some common ones only; not flexible
//
// - HMAC_sha512, sha1, sha256
// - single-shot
//
#include "py/runtime.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "my_assert.h"

#if MICROPY_SSL_MBEDTLS
# include "mbedtls/md.h"
#endif

STATIC mp_obj_t hmac_X(int md_size, mp_obj_t key_in, mp_obj_t msg_in)
{
    mp_buffer_info_t key, msg;
    mp_get_buffer_raise(key_in, &key, MP_BUFFER_READ);
    mp_get_buffer_raise(msg_in, &msg, MP_BUFFER_READ);

    vstr_t rv_out;
    vstr_init_len(&rv_out, md_size);

#if MICROPY_SSL_MBEDTLS
    const mbedtls_md_info_t *algo;

    switch(md_size) {
        case 64:
            algo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
            break;
        case 32:
            algo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
            break;
        case 20:
            algo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
            break;
        default:
            mp_raise_ValueError(NULL);
    }

    int x = mbedtls_md_hmac(algo, key.buf, key.len, msg.buf, msg.len, (uint8_t*)rv_out.buf);

    if(x) {
        mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("mbedtls_md_hmac"));
    }

#else
// XXX add code here
// - secp256k1_hmac_sha256_initialize
    mp_raise_ValueError(NULL);
#if 0
    if(md_size == 32) {
        secp256k1_sha256    ctx;

        secp256k1_sha256_initialize(secp256k1_sha256 *hash);
        secp256k1_sha256_write(secp256k1_sha256 *hash, const unsigned char *data, size_t size);
        secp256k1_sha256_finalize(secp256k1_sha256 *hash, unsigned char *out32);
    }
#endif
#endif

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv_out);
}

STATIC mp_obj_t hmac_sha512(mp_obj_t key_in, mp_obj_t msg_in)
{
    return hmac_X(64, key_in, msg_in);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(hmac_sha512_obj, hmac_sha512);

STATIC mp_obj_t hmac_sha256(mp_obj_t key_in, mp_obj_t msg_in)
{
    return hmac_X(32, key_in, msg_in);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(hmac_sha256_obj, hmac_sha256);

STATIC mp_obj_t hmac_sha1(mp_obj_t key_in, mp_obj_t msg_in)
{
    return hmac_X(20, key_in, msg_in);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(hmac_sha1_obj, hmac_sha1);


STATIC const mp_rom_map_elem_t mp_module_hmac_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hmac) },

    { MP_ROM_QSTR(MP_QSTR_hmac_sha512), MP_ROM_PTR(&hmac_sha512_obj) },
    { MP_ROM_QSTR(MP_QSTR_hmac_sha256), MP_ROM_PTR(&hmac_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_hmac_sha1), MP_ROM_PTR(&hmac_sha1_obj) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_hmac_globals, mp_module_hmac_globals_table);

const mp_obj_module_t mp_module_hmac = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_hmac_globals,
};

