// 
// secp256k1 - the Bitcoin curve
//
// - sign, verify sig, pubkey recovery from sig
// - the famous 256-bit curve only
// - assume all signatures include recid for pubkey recovery (65 bytes)
// - see test_k1.py
//
#include "py/runtime.h"
#include "random.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#include "secp256k1.h"
#include "secp256k1_recovery.h"
#include "secp256k1_extrakeys.h"

typedef struct  {
    mp_obj_base_t base;
    secp256k1_pubkey    pubkey;         // not allocated
} mp_obj_pubkey_t;

typedef struct  {
    mp_obj_base_t base;
    secp256k1_ecdsa_recoverable_signature   sig;
} mp_obj_sig_t;

typedef struct  {
    mp_obj_base_t base;
    uint8_t             privkey[32];
    secp256k1_keypair   keypair;
} mp_obj_keypair_t;

STATIC const mp_obj_type_t s_pubkey_type;
STATIC const mp_obj_type_t s_sig_type;
STATIC const mp_obj_type_t s_keypair_type;

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

// big heavy shared object for all calls
static void _setup_ctx(void)
{
    lib_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY 
                                            | SECP256K1_CONTEXT_SIGN
                                            | SECP256K1_CONTEXT_DECLASSIFY);
    if(!lib_ctx) {
        mp_raise_msg(&mp_type_MemoryError, MP_ERROR_TEXT("secp256k1_context_create"));
    }

    secp256k1_context_set_illegal_callback(lib_ctx, s_illegal_cb, NULL);
    secp256k1_context_set_error_callback(lib_ctx, s_error_cb, NULL);
}

// Constructor for signature
STATIC mp_obj_t s_sig_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_sig_t *o = m_new_obj(mp_obj_sig_t);
    o->base.type = type;

    if(!lib_ctx) _setup_ctx();

    mp_buffer_info_t inp;
    mp_get_buffer_raise(args[0], &inp, MP_BUFFER_READ);
    const uint8_t *bi = (uint8_t *)inp.buf;

    // expect raw recid+32+32 bytes 
    if(inp.len != 65) {
        mp_raise_ValueError(MP_ERROR_TEXT("sig len != 65"));
    }

    // in bitcoin world, first byte encodes recid.
    int recid = (bi[0] - 27) & 0x3;
    
    int rv = secp256k1_ecdsa_recoverable_signature_parse_compact(lib_ctx,
                        &o->sig, &bi[1], recid);

    if(rv != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("parse sig"));
    }

    return MP_OBJ_FROM_PTR(o);
}


// Constructor for pubkey
STATIC mp_obj_t s_pubkey_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_pubkey_t *o = m_new_obj(mp_obj_pubkey_t);
    o->base.type = type;

    if(!lib_ctx) _setup_ctx();

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

    if(!lib_ctx) _setup_ctx();

    vstr_t vstr;
    vstr_init_len(&vstr, 66);

    // default: compressed, but can pass in true to get uncompressed
    bool compressed = true;
    if(n_args > 1) {
        compressed = !mp_obj_is_true(args[1]);
    }

    size_t outlen = vstr.len;
    secp256k1_ec_pubkey_serialize(lib_ctx, (uint8_t *)vstr.buf, &outlen,
            &self->pubkey,
            compressed ? SECP256K1_EC_COMPRESSED: SECP256K1_EC_UNCOMPRESSED );

    vstr.len = outlen;
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_pubkey_to_bytes_obj, 1, 2, s_pubkey_to_bytes);

// output signature as 65 bytes
STATIC mp_obj_t s_sig_to_bytes(mp_obj_t self_in) {
    mp_obj_sig_t *self = MP_OBJ_TO_PTR(self_in);

    if(!lib_ctx) _setup_ctx();

    int recid = 0;
    vstr_t vstr;
    vstr_init_len(&vstr, 65);

    secp256k1_ecdsa_recoverable_signature_serialize_compact(lib_ctx,
                ((uint8_t *)vstr.buf)+1, &recid, &self->sig);

    // first byte is bitcoin-specific rec id
    // - always compressed
    vstr.buf[0] = 27 + recid + 4;

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_sig_to_bytes_obj, s_sig_to_bytes);

// verify sig (and recovery pubkey)
STATIC mp_obj_t s_sig_verify_recover(mp_obj_t self_in, mp_obj_t digest_in)
{
    mp_obj_sig_t *self = MP_OBJ_TO_PTR(self_in);

    mp_buffer_info_t digest;
    mp_get_buffer_raise(digest_in, &digest, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("md len != 32"));
    }

    mp_obj_pubkey_t *rv = m_new_obj(mp_obj_pubkey_t);
    rv->base.type = &s_pubkey_type;

    int x = secp256k1_ecdsa_recover(lib_ctx, &rv->pubkey,  &self->sig, digest.buf);

    if(x != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("verify/recover sig"));
    }
    
    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_sig_verify_recover_obj, s_sig_verify_recover);


STATIC mp_obj_t s_sign(mp_obj_t privkey_in, mp_obj_t digest_in)
{
    if(!lib_ctx) _setup_ctx();

    mp_buffer_info_t digest;
    mp_get_buffer_raise(digest_in, &digest, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("md len != 32"));
    }

    mp_buffer_info_t privkey;
    uint8_t *pk;

    if(mp_obj_get_type(privkey_in) == &s_keypair_type) {
        // mp_obj_keypair_t as first arg
        mp_obj_keypair_t *keypair = MP_OBJ_TO_PTR(privkey_in);
        pk = keypair->privkey;
    } else {
        // typical: raw privkey
        mp_get_buffer_raise(privkey_in, &privkey, MP_BUFFER_READ);
        if(privkey.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("privkey len != 32"));
        }
        pk = privkey.buf;
    }

    mp_obj_sig_t *rv = m_new_obj(mp_obj_sig_t);
    rv->base.type = &s_sig_type;

    int x = secp256k1_ecdsa_sign_recoverable(lib_ctx, &rv->sig, digest.buf, pk, secp256k1_nonce_function_default, NULL);
    if(x != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("verify/recover sig"));
    }
    
    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_sign_obj, s_sign);

// KEY PAIRS (private key, with public key computed)

// Constructor for keypair
STATIC mp_obj_t s_keypair_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);

    mp_obj_keypair_t *o = m_new_obj(mp_obj_keypair_t);
    o->base.type = type;

    if(!lib_ctx) _setup_ctx();

    if(n_args == 0) {
        // pick random key
        my_random_bytes(o->privkey, 32);
    } else {
        mp_buffer_info_t inp;
        mp_get_buffer_raise(args[0], &inp, MP_BUFFER_READ);
        if(inp.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("privkey len != 32"));
        }

        memcpy(o->privkey, (uint8_t *)inp.buf, 32);
    }

    // always generate keypair based on secret
    int x = secp256k1_keypair_create(lib_ctx, &o->keypair, o->privkey);

    if((x == 0) && (n_args == 0)) {
        my_random_bytes(o->privkey, 32);
        x = secp256k1_keypair_create(lib_ctx, &o->keypair, o->privkey);
        // single rety only, because no-one is that unlucky
    }
    if(x == 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_keypair_create"));
    }

    return MP_OBJ_FROM_PTR(o);
}


// METHODS

STATIC mp_obj_t s_keypair_privkey(mp_obj_t self_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    return mp_obj_new_bytes(self->privkey, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_keypair_privkey_obj, s_keypair_privkey);

STATIC mp_obj_t s_keypair_pubkey(mp_obj_t self_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    if(!lib_ctx) _setup_ctx();

    // no need to cache, already done by keypair code
    mp_obj_pubkey_t *rv = m_new_obj(mp_obj_pubkey_t);
    rv->base.type = &s_pubkey_type;

    int x = secp256k1_keypair_pub(lib_ctx, &rv->pubkey, &self->keypair);
    if(x != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_keypair_pub"));
    }

    return rv;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_keypair_pubkey_obj, s_keypair_pubkey);


// sigs and what you can do with them
STATIC const mp_rom_map_elem_t s_sig_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_sig_to_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify_recover), MP_ROM_PTR(&s_sig_verify_recover_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_sig_locals_dict, s_sig_locals_dict_table);

STATIC const mp_obj_type_t s_sig_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_sig,
    .make_new = s_sig_make_new,
    .locals_dict = (void *)&s_sig_locals_dict,
};


// pubkeys and what you can do with them
STATIC const mp_rom_map_elem_t s_pubkey_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_pubkey_to_bytes_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_pubkey_locals_dict, s_pubkey_locals_dict_table);

STATIC const mp_obj_type_t s_pubkey_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_pubkey,
    .make_new = s_pubkey_make_new,
    .locals_dict = (void *)&s_pubkey_locals_dict,
};

// privkeys and what you can do with them
STATIC const mp_rom_map_elem_t s_keypair_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_privkey), MP_ROM_PTR(&s_keypair_privkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_keypair_pubkey_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_keypair_locals_dict, s_keypair_locals_dict_table);

STATIC const mp_obj_type_t s_keypair_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_privkey,
    .make_new = s_keypair_make_new,
    .locals_dict = (void *)&s_keypair_locals_dict,
};


STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_secp256k1) },

    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_pubkey_type) },
    { MP_ROM_QSTR(MP_QSTR_keypair), MP_ROM_PTR(&s_keypair_type) },
    { MP_ROM_QSTR(MP_QSTR_signature), MP_ROM_PTR(&s_sig_type) },
    { MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&s_sign_obj) },

};

STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_secp256k1 = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
