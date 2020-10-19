// 
// secp256k1 - the Bitcoin curve
//
// - sign, verify sig, pubkey recovery from sig
// - the famous 256 bit curve only
//
#include "py/runtime.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "secp256k1.h"

typedef struct  {
    mp_obj_base_t base;
    secp256k1_pubkey    pubkey;         // not allocated
} mp_obj_pubkey_t;

// Shared context for all ops. Never freed.
secp256k1_context   *lib_ctx;

static void s_illegal_cb(const char* message, void* data)
{
    mp_raise_ValueError(message);
}
static void s_error_cb(const char* message, void* data)
{
    mp_raise_ValueError(message);
}

// Constructor for pubkey
STATIC mp_obj_t s_pubkey_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_pubkey_t *o = m_new_obj(mp_obj_pubkey_t);
    o->base.type = type;

    if(!lib_ctx) {
        lib_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY 
                                                | SECP256K1_CONTEXT_SIGN
                                                | SECP256K1_CONTEXT_DECLASSIFY);
        if(!lib_ctx) {
            mp_raise_msg(&mp_type_MemoryError, MP_ERROR_TEXT("secp256k1_context_create"));
        }

        secp256k1_context_set_illegal_callback(lib_ctx, s_illegal_cb, NULL);
        secp256k1_context_set_error_callback(lib_ctx, s_error_cb, NULL);
    }

    mp_buffer_info_t inp;
    mp_get_buffer_raise(args[0], &inp, MP_BUFFER_READ);
    
    int rv = secp256k1_ec_pubkey_parse(lib_ctx, &o->pubkey, inp.buf, inp.len);

    if(rv != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ec_pubkey_parse"));
    }

    return MP_OBJ_FROM_PTR(o);
}

// output pubkey
STATIC mp_obj_t s_pubkey_to_bytes(size_t n_args, const mp_obj_t *args) {
    mp_obj_pubkey_t *self = MP_OBJ_TO_PTR(args[0]);

    vstr_t vstr;
    vstr_init_len(&vstr, 66);

    // default: compressed, but can pass in true to get uncompressed
    bool compressed = true;
    if(n_args > 1) {
        compressed = !mp_obj_get_int(args[1]);
    }

    size_t outlen = vstr.len;
    secp256k1_ec_pubkey_serialize(lib_ctx, (uint8_t *)vstr.buf, &outlen,
            &self->pubkey,
            compressed ? SECP256K1_EC_COMPRESSED: SECP256K1_EC_UNCOMPRESSED );

    vstr.len = outlen;
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_pubkey_to_bytes_obj, 1, 2, s_pubkey_to_bytes);


STATIC const mp_rom_map_elem_t s_pubkey_locals_dict_table[] = {
    // pubkeys and what you can do with them
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_pubkey_to_bytes_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_pubkey_locals_dict, s_pubkey_locals_dict_table);

STATIC const mp_obj_type_t s_pubkey_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_pubkey,
    .make_new = s_pubkey_make_new,
    .locals_dict = (void *)&s_pubkey_locals_dict,
};

STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_secp256k1) },

    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_pubkey_type) },
/*
    { MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&curve_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&curve_verify_obj) },
*/

};

STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_secp256k1 = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
