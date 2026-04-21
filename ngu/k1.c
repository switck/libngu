// 
// secp256k1 - the Bitcoin curve
//
// - sign, verify sig, pubkey recovery from sig
// - the famous 256-bit curve only
// - assume all signatures include recid for pubkey recovery (65 bytes)
// - see test_k1.py
//
#include "py/runtime.h"
#include "py/objlist.h" // For list-related functions
#include "random.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "my_assert.h"

#include "sec_shared.h"

#if MICROPY_SSL_MBEDTLS
#include "mbedtls/sha256.h"
#else
#include "extmod/crypto-algorithms/sha256.h"
#endif

typedef struct  {
    mp_obj_base_t base;
    secp256k1_pubkey    pubkey;         // not allocated
} mp_obj_pubkey_t;

typedef struct  {
    mp_obj_base_t base;
    secp256k1_xonly_pubkey    pubkey;         // not allocated
    int    parity;
} mp_obj_xonly_pubkey_t;

typedef struct  {
    mp_obj_base_t base;
    secp256k1_ecdsa_recoverable_signature   sig;
} mp_obj_sig_t;

typedef struct  {
    mp_obj_base_t base;
    secp256k1_keypair   keypair;
} mp_obj_keypair_t;

// MuSig2 types
typedef struct {
    mp_obj_base_t base;
    secp256k1_musig_pubnonce pubnonce;
} mp_obj_musig_pubnonce_t;

typedef struct {
    mp_obj_base_t base;
    secp256k1_musig_secnonce secnonce;
} mp_obj_musig_secnonce_t;

typedef struct {
    mp_obj_base_t base;
    secp256k1_musig_aggnonce aggnonce;
} mp_obj_musig_aggnonce_t;

typedef struct {
    mp_obj_base_t base;
    secp256k1_musig_keyagg_cache keyagg_cache;
} mp_obj_musig_keyagg_cache_t;

typedef struct {
    mp_obj_base_t base;
    secp256k1_musig_session session;
} mp_obj_musig_session_t;

typedef struct {
    mp_obj_base_t base;
    secp256k1_musig_partial_sig sig;
} mp_obj_musig_partial_sig_t;


STATIC const mp_obj_type_t s_pubkey_type;
STATIC const mp_obj_type_t s_xonly_pubkey_type;
STATIC const mp_obj_type_t s_sig_type;
STATIC const mp_obj_type_t s_keypair_type;
STATIC const mp_obj_type_t s_musig_pubnonce_type;
STATIC const mp_obj_type_t s_musig_secnonce_type;
STATIC const mp_obj_type_t s_musig_aggnonce_type;
STATIC const mp_obj_type_t s_musig_keyagg_cache_type;
STATIC const mp_obj_type_t s_musig_session_type;
STATIC const mp_obj_type_t s_musig_partial_sig_type;

// Shared context for all major ops.
secp256k1_context   *lib_ctx;

void secp256k1_default_illegal_callback_fn(const char* message, void* data)
{
#ifndef MICROPY_ROM_TEXT_COMPRESSION
    mp_raise_ValueError(message);
#else
    mp_raise_ValueError(MP_ERROR_TEXT("secp256k1 illegal"));
#endif
}

void secp256k1_default_error_callback_fn(const char* message, void* data)
{
#ifndef MICROPY_ROM_TEXT_COMPRESSION
    mp_raise_ValueError(message);
#else
    mp_raise_ValueError(MP_ERROR_TEXT("secp256k1 error"));
#endif
}

void ctx_randomize(void) {
	uint8_t randomize[32];
	my_random_bytes(randomize, 32);
	int return_val = secp256k1_context_randomize(lib_ctx, randomize);
    if(!return_val) {
    	mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_context_randomize"));
    }
}

void sec_setup_ctx(void)
{
    if(lib_ctx) return;

    // make big heavy shared object for all calls
    const uint32_t flags = SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN;

    size_t need = secp256k1_context_preallocated_size(flags);
    //printf("need = 0x%x\n\n", (int)need);            // = 0x20e0 on unix, 0x20c0 on esp32, stm32

    // need to protect this data from GC, so make a fake module to hold it
    uint8_t *ws = m_malloc(need);
    mp_obj_t *xx = mp_obj_new_bytearray_by_ref(need, ws);
    mp_obj_t mod_obj = mp_obj_new_module(MP_QSTR__ngu_workspace);
    mp_obj_dict_t *globals = mp_obj_module_get_globals(mod_obj);

    mp_obj_dict_store(globals, MP_ROM_QSTR(MP_QSTR__ngu_workspace), xx);

    lib_ctx = secp256k1_context_preallocated_create(ws, flags);

    if(!lib_ctx) {
        mp_raise_msg(&mp_type_MemoryError, MP_ERROR_TEXT("secp256k1_context_preallocated_create"));
    }
	ctx_randomize();

    // static error callbacks already in place above, no need to setup
}

STATIC mp_obj_t s_ctx_rnd(void) {
    sec_setup_ctx();
    ctx_randomize();
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_0(s_ctx_rnd_obj, s_ctx_rnd);

// Constructor for signature
STATIC mp_obj_t s_sig_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_sig_t *o = m_new_obj(mp_obj_sig_t);
    o->base.type = type;

    sec_setup_ctx();

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

    mp_buffer_info_t inp;
    mp_get_buffer_raise(args[0], &inp, MP_BUFFER_READ);
    
    int rv = secp256k1_ec_pubkey_parse(secp256k1_context_static, &o->pubkey, inp.buf, inp.len);

    if(rv != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ec_pubkey_parse"));
    }

    return MP_OBJ_FROM_PTR(o);
}

// Constructor for xonly pubkey
STATIC mp_obj_t s_xonly_pubkey_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_xonly_pubkey_t *o = m_new_obj(mp_obj_xonly_pubkey_t);
    o->base.type = type;

    mp_buffer_info_t inp;
    mp_get_buffer_raise(args[0], &inp, MP_BUFFER_READ);
    if(inp.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("xonly pubkey len != 32"));
    }
    int ok = secp256k1_xonly_pubkey_parse(secp256k1_context_static, &o->pubkey, inp.buf);

    if(ok != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_xonly_pubkey_parse"));
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
        compressed = !mp_obj_is_true(args[1]);
    }

    size_t outlen = vstr.len;
    secp256k1_ec_pubkey_serialize(secp256k1_context_static, (uint8_t *)vstr.buf, &outlen,
            &self->pubkey,
            compressed ? SECP256K1_EC_COMPRESSED: SECP256K1_EC_UNCOMPRESSED );

    vstr.len = outlen;
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_pubkey_to_bytes_obj, 1, 2, s_pubkey_to_bytes);


STATIC mp_obj_t s_pubkey_to_xonly(mp_obj_t self_in){
    mp_obj_pubkey_t *self = MP_OBJ_TO_PTR(self_in);

    mp_obj_xonly_pubkey_t *xonly = m_new_obj(mp_obj_xonly_pubkey_t);
    xonly->base.type = &s_xonly_pubkey_type;

    int ok = secp256k1_xonly_pubkey_from_pubkey(secp256k1_context_static, &xonly->pubkey, &xonly->parity, &self->pubkey);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_xonly_pubkey_from_pubkey"));
    }
    return MP_OBJ_FROM_PTR(xonly);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_pubkey_to_xonly_obj, s_pubkey_to_xonly);


// output xonly pubkey
STATIC mp_obj_t s_xonly_pubkey_to_bytes(size_t n_args, const mp_obj_t *args) {
    mp_obj_xonly_pubkey_t *self = MP_OBJ_TO_PTR(args[0]);

    vstr_t vstr;
    vstr_init_len(&vstr, 32);

    secp256k1_xonly_pubkey_serialize(secp256k1_context_static, (uint8_t *)vstr.buf, &self->pubkey);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_xonly_pubkey_to_bytes_obj, 1, 2, s_xonly_pubkey_to_bytes);

// output xonly pubkey parity
STATIC mp_obj_t s_xonly_pubkey_parity(mp_obj_t self_in) {
    mp_obj_xonly_pubkey_t *self = MP_OBJ_TO_PTR(self_in);
    return mp_obj_new_int(self->parity);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_xonly_pubkey_parity_obj, s_xonly_pubkey_parity);

// add tweak32 to xonly pubkey
STATIC mp_obj_t s_xonly_pubkey_tweak_add(mp_obj_t self_in, mp_obj_t tweak32_in) {
    int rc;
    mp_buffer_info_t tweak32;
    mp_get_buffer_raise(tweak32_in, &tweak32, MP_BUFFER_READ);
    if(tweak32.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("tweak32 len != 32"));
    }
    mp_obj_xonly_pubkey_t *self = MP_OBJ_TO_PTR(self_in);

    secp256k1_pubkey pk;
    rc = secp256k1_xonly_pubkey_tweak_add(secp256k1_context_static, &pk, &self->pubkey, tweak32.buf);
    if(rc != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_xonly_pubkey_tweak_add"));
    }
    //  create new tweaked object rather than updating self
    mp_obj_xonly_pubkey_t *rv = m_new_obj(mp_obj_xonly_pubkey_t);
    rv->base.type = &s_xonly_pubkey_type;
    rc = secp256k1_xonly_pubkey_from_pubkey(secp256k1_context_static, &rv->pubkey, &rv->parity, &pk);
    if(rc != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_xonly_pubkey_from_pubkey"));
    }
    return MP_OBJ_FROM_PTR(rv);

}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_xonly_pubkey_tweak_add_obj, s_xonly_pubkey_tweak_add);

// output signature as 65 bytes
STATIC mp_obj_t s_sig_to_bytes(mp_obj_t self_in) {
    mp_obj_sig_t *self = MP_OBJ_TO_PTR(self_in);

    int recid = 0;
    vstr_t vstr;
    vstr_init_len(&vstr, 65);

    secp256k1_ecdsa_recoverable_signature_serialize_compact(secp256k1_context_static,
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


STATIC mp_obj_t s_sign(mp_obj_t privkey_in, mp_obj_t digest_in, mp_obj_t counter_in)
{
    sec_setup_ctx();

    mp_buffer_info_t digest;
    mp_get_buffer_raise(digest_in, &digest, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("md len != 32"));
    }

    mp_buffer_info_t privkey;
    uint8_t pk[32];

    if(mp_obj_get_type(privkey_in) == &s_keypair_type) {
        // mp_obj_keypair_t as first arg
        mp_obj_keypair_t *keypair = MP_OBJ_TO_PTR(privkey_in);
	    secp256k1_keypair_sec(lib_ctx, pk, &keypair->keypair);
    } else {
        // typical: raw privkey
        mp_get_buffer_raise(privkey_in, &privkey, MP_BUFFER_READ);
        if(privkey.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("privkey len != 32"));
        }
        memcpy(pk, privkey.buf, 32);
    }

    mp_obj_sig_t *rv = m_new_obj(mp_obj_sig_t);
    rv->base.type = &s_sig_type;

    // allow grinding of different nonce values
    int counter = mp_obj_get_int_truncated(counter_in);
    uint32_t    nonce_data[8] = { counter, 0, };
    uint8_t     *nonce_ptr = counter ? ((uint8_t *)nonce_data) : NULL;

    int x = secp256k1_ecdsa_sign_recoverable(lib_ctx, &rv->sig, digest.buf, pk,
                                                secp256k1_nonce_function_default, nonce_ptr);
    if(x != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("verify/recover sig"));
    }
    
    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_sign_obj, s_sign);


STATIC mp_obj_t s_verify_schnorr(mp_obj_t compact_sig_in, mp_obj_t digest_in, mp_obj_t xonly_pubkey_in) {
    mp_buffer_info_t compact_sig;
    mp_get_buffer_raise(compact_sig_in, &compact_sig, MP_BUFFER_READ);
    if(compact_sig.len != 64) {
        mp_raise_ValueError(MP_ERROR_TEXT("compact sig len != 64"));
    }

    if(mp_obj_get_type(xonly_pubkey_in) != &s_xonly_pubkey_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("xonly pubkey type"));
    }

    mp_buffer_info_t digest;
    mp_get_buffer_raise(digest_in, &digest, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("md len != 32"));
    }

    mp_obj_xonly_pubkey_t *xonly_pub = MP_OBJ_TO_PTR(xonly_pubkey_in);
    int ok = secp256k1_schnorrsig_verify(secp256k1_context_static, compact_sig.buf, digest.buf, digest.len, &xonly_pub->pubkey);
    if (ok != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_schnorrsig_verify"));
    }
    return mp_obj_new_int(ok);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_verify_schnorr_obj, s_verify_schnorr);


STATIC mp_obj_t s_sign_schnorr(mp_obj_t privkey_in, mp_obj_t digest_in, mp_obj_t aux_rand_in)
{
    sec_setup_ctx();

    mp_buffer_info_t digest;
    mp_get_buffer_raise(digest_in, &digest, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("md len != 32"));
    }
    mp_buffer_info_t aux_rand;
    mp_get_buffer_raise(aux_rand_in, &aux_rand, MP_BUFFER_READ);
    if(aux_rand.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("aux rand len != 32"));
    }

    vstr_t rv;
    vstr_init_len(&rv, 64);

    int ok;
    if(mp_obj_get_type(privkey_in) == &s_keypair_type) {
    	mp_obj_keypair_t *keypair = MP_OBJ_TO_PTR(privkey_in);
        ok = secp256k1_schnorrsig_sign32(lib_ctx, (uint8_t *)rv.buf, digest.buf, &keypair->keypair, aux_rand.buf);
    } else {
        // typical: raw privkey
        mp_buffer_info_t privkey;
        mp_get_buffer_raise(privkey_in, &privkey, MP_BUFFER_READ);
        if(privkey.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("privkey len != 32"));
        }
        int key_ok;
		secp256k1_keypair keypair;
		key_ok = secp256k1_keypair_create(lib_ctx, &keypair, privkey.buf);
		if (!key_ok) {
			mp_raise_ValueError(MP_ERROR_TEXT("invalid secret"));
		}
        ok = secp256k1_schnorrsig_sign32(lib_ctx, (uint8_t *)rv.buf, digest.buf, &keypair, aux_rand.buf);
    }
    if(!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_schnorrsig_sign"));
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_sign_schnorr_obj, s_sign_schnorr);

// KEY PAIRS (private key, with public key computed)

// Constructor for keypair
STATIC mp_obj_t s_keypair_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);

    mp_obj_keypair_t *o = m_new_obj(mp_obj_keypair_t);
    o->base.type = type;

    sec_setup_ctx();

    uint8_t seckey[32];
    if(n_args == 0) {
        // pick random key
        my_random_bytes(seckey, 32);
    } else {
        mp_buffer_info_t inp;
        mp_get_buffer_raise(args[0], &inp, MP_BUFFER_READ);
        if(inp.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("privkey len != 32"));
        }

        memcpy(seckey, inp.buf, 32);
    }

    // always generate keypair based on secret
    int x = secp256k1_keypair_create(lib_ctx, &o->keypair, seckey);

    if((x == 0) && (n_args == 0)) {
        my_random_bytes(seckey, 32);
        x = secp256k1_keypair_create(lib_ctx, &o->keypair, seckey);
        // single rety only, because no-one is that unlucky
    }
    if(x == 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_keypair_create"));
    }

    return MP_OBJ_FROM_PTR(o);
}


// keypair METHODS

STATIC mp_obj_t s_keypair_privkey(mp_obj_t self_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    uint8_t seckey[32];
	secp256k1_keypair_sec(lib_ctx, seckey, &self->keypair);

    return mp_obj_new_bytes(seckey, 32);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_keypair_privkey_obj, s_keypair_privkey);

STATIC mp_obj_t s_keypair_pubkey(mp_obj_t self_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    sec_setup_ctx();

    // no need to cache, already done by keypair code
    mp_obj_pubkey_t *rv = m_new_obj(mp_obj_pubkey_t);
    rv->base.type = &s_pubkey_type;

    int x = secp256k1_keypair_pub(lib_ctx, &rv->pubkey, &self->keypair);
    if(x != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_keypair_pub"));
    }

    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_keypair_pubkey_obj, s_keypair_pubkey);

STATIC mp_obj_t s_keypair_xonly_pubkey(mp_obj_t self_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    sec_setup_ctx();

    // no need to cache, already done by keypair code
    mp_obj_xonly_pubkey_t *rv = m_new_obj(mp_obj_xonly_pubkey_t);
    rv->base.type = &s_xonly_pubkey_type;

    int ok = secp256k1_keypair_xonly_pub(lib_ctx, &rv->pubkey, &rv->parity, &self->keypair);
    if(ok != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_keypair_xonly_pub"));
    }

    return MP_OBJ_FROM_PTR(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_keypair_xonly_pubkey_obj, s_keypair_xonly_pubkey);

STATIC mp_obj_t s_keypair_xonly_tweak_add(mp_obj_t self_in, mp_obj_t tweak32_in) {
    //  Tweak a keypair by adding tweak32 to the secret key and updating the public
    //  key accordingly.
    mp_buffer_info_t tweak32;
    mp_get_buffer_raise(tweak32_in, &tweak32, MP_BUFFER_READ);
    if(tweak32.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("tweak32 len != 32"));
    }
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);
    //  create new tweaked object rather than updating self
    mp_obj_keypair_t *rv = m_new_obj(mp_obj_keypair_t);
    rv->base.type = &s_keypair_type;

    sec_setup_ctx();

    uint8_t seckey[32];
	secp256k1_keypair_sec(lib_ctx, seckey, &self->keypair);

    int key_ok = secp256k1_keypair_create(lib_ctx, &rv->keypair, seckey);
    if(key_ok != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_keypair_xonly_tweak_add secp256k1_keypair_create"));
    }

    int ok = secp256k1_keypair_xonly_tweak_add(lib_ctx, &rv->keypair, tweak32.buf);
    if(ok != 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_keypair_xonly_tweak_add invalid arguments"));
    }

    return MP_OBJ_FROM_PTR(rv);

}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_keypair_xonly_tweak_add_obj, s_keypair_xonly_tweak_add);

static int _my_ecdh_hash(uint8_t *output, const uint8_t *x32, const uint8_t *y32, void *data) {
    (void)data;

#if MICROPY_SSL_MBEDTLS

    mbedtls_sha256_context ctx;

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, x32, 32);
    mbedtls_sha256_update_ret(&ctx, y32, 32);
    mbedtls_sha256_finish_ret(&ctx, output);
    mbedtls_sha256_free(&ctx);

#else
    // see extmod/crypto-algorithms/sha256.h
    CRYAL_SHA256_CTX    ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, x32, 32);
    sha256_update(&ctx, y32, 32);
    sha256_final(&ctx, output);
#endif

    return 1;
}

STATIC mp_obj_t s_keypair_ecdh_multiply(mp_obj_t self_in, mp_obj_t other_point_in) {
    mp_obj_keypair_t *self = MP_OBJ_TO_PTR(self_in);

    // returns sha256(pubkey64(privkey * other_pubkey_point))
    sec_setup_ctx();

    mp_buffer_info_t inp;
    mp_get_buffer_raise(other_point_in, &inp, MP_BUFFER_READ);

    secp256k1_pubkey    other_point;
    int ok = secp256k1_ec_pubkey_parse(lib_ctx, &other_point, inp.buf, inp.len);
    if(!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ec_pubkey_parse"));
    }

    uint8_t seckey[32];
	secp256k1_keypair_sec(lib_ctx, seckey, &self->keypair);

    vstr_t rv;
    vstr_init_len(&rv, 32);

    ok = secp256k1_ecdh(lib_ctx, (uint8_t *)rv.buf, &other_point, seckey, _my_ecdh_hash, NULL);
    if(!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ecdh"));
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_keypair_ecdh_multiply_obj, s_keypair_ecdh_multiply);


// MuSig2

STATIC mp_obj_t s_musig_keyagg_cache_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_obj_musig_keyagg_cache_t *cache = m_new_obj(mp_obj_musig_keyagg_cache_t);
	cache->base.type = type;

    return MP_OBJ_FROM_PTR(cache);
}


STATIC mp_obj_t s_musig_pubkey_agg(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {

	STATIC const mp_arg_t allowed_args[] = {
        { MP_QSTR_pubkeys,        MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL} },
        { MP_QSTR_keyagg_cache,                     MP_ARG_OBJ, {.u_obj = mp_const_none} },
        { MP_QSTR_sort,                             MP_ARG_OBJ, {.u_obj = mp_const_true} },
    };

    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    if (!mp_obj_is_type(args[0].u_obj, &mp_type_list)) {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected a list object"));
    }
    mp_obj_list_t *pubkeys = MP_OBJ_TO_PTR(args[0].u_obj);

    size_t len_pubkeys = pubkeys->len;
    if (!len_pubkeys){
        mp_raise_ValueError(MP_ERROR_TEXT("Empty pubkeys list"));
    }

    // Handle the case where key aggregation cache is not provided
    // this is allowed when user only wants to aggregate without intention to sign
    secp256k1_musig_keyagg_cache *keyagg_cache_ptr = NULL;
    if (args[1].u_obj != mp_const_none) {
        if(mp_obj_get_type(args[1].u_obj) != &s_musig_keyagg_cache_type) {
            mp_raise_TypeError(MP_ERROR_TEXT("key aggregation cache type"));
        }
        mp_obj_musig_keyagg_cache_t *cache = MP_OBJ_TO_PTR(args[1].u_obj);
        keyagg_cache_ptr = &cache->keyagg_cache;
    }

    // remap to array of secp256k1_pubkey pointers
    const secp256k1_pubkey *pks[len_pubkeys];
    for (size_t i = 0; i < len_pubkeys; i++) {
        if(mp_obj_get_type(pubkeys->items[i]) != &s_pubkey_type) {
            mp_raise_TypeError(MP_ERROR_TEXT("pubkeys: pubkey type"));
        }
        mp_obj_pubkey_t *pk = pubkeys->items[i];
        pks[i] = &pk->pubkey;
    }

    int ok;
    // default is to sort the pubkeys - so aggregate key is always the same from same set of keys regardless of order
    bool sort_pubkeys = (args[2].u_obj == mp_const_true);
    if (sort_pubkeys){
        ok = secp256k1_ec_pubkey_sort(secp256k1_context_static, pks, len_pubkeys);
        if (!ok){
            mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_ec_pubkey_sort invalid arguments"));
        }
    }

    // newly created aggregate x-only pubkey returned by this function
    mp_obj_xonly_pubkey_t *xonly = m_new_obj(mp_obj_xonly_pubkey_t);
    xonly->base.type = &s_xonly_pubkey_type;

    ok = secp256k1_musig_pubkey_agg(secp256k1_context_static, &xonly->pubkey, keyagg_cache_ptr,
                                    pks, len_pubkeys);
    if (!ok){
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_pubkey_agg invalid arguments"));
    }
    return MP_OBJ_FROM_PTR(xonly);
}
MP_DEFINE_CONST_FUN_OBJ_KW(s_musig_pubkey_agg_obj, 1, s_musig_pubkey_agg);


// when non-xonly aggregate pubkey is needed
STATIC mp_obj_t s_musig_pubkey_get(mp_obj_t keyagg_cache_in){

    mp_obj_musig_keyagg_cache_t *cache = MP_OBJ_TO_PTR(keyagg_cache_in);

    mp_obj_pubkey_t *pubkey = m_new_obj(mp_obj_pubkey_t);
    pubkey->base.type = &s_pubkey_type;

    int ok = secp256k1_musig_pubkey_get(secp256k1_context_static, &pubkey->pubkey, &cache->keyagg_cache);
    if (!ok){
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_pubkey_agg invalid arguments"));
    }
    return MP_OBJ_FROM_PTR(pubkey);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_musig_pubkey_get_obj, s_musig_pubkey_get);


STATIC mp_obj_t s_musig_pubkey_ec_tweak_add(mp_obj_t keyagg_cache_in, mp_obj_t tweak32_in){

    if(mp_obj_get_type(keyagg_cache_in) != &s_musig_keyagg_cache_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("key aggregation cache type"));
    }

    mp_obj_musig_keyagg_cache_t *cache = MP_OBJ_TO_PTR(keyagg_cache_in);

    mp_buffer_info_t tweak32;
    mp_get_buffer_raise(tweak32_in, &tweak32, MP_BUFFER_READ);
    if(tweak32.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("tweak32 len != 32"));
    }

    mp_obj_pubkey_t *res = m_new_obj(mp_obj_pubkey_t);
    res->base.type = &s_pubkey_type;

    int ok = secp256k1_musig_pubkey_ec_tweak_add(secp256k1_context_static, &res->pubkey,
                                                 &cache->keyagg_cache, tweak32.buf);
    if (!ok){
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_pubkey_ec_tweak_add invalid arguments"));
    }

    return MP_OBJ_FROM_PTR(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_musig_pubkey_ec_tweak_add_obj, s_musig_pubkey_ec_tweak_add);


STATIC mp_obj_t s_musig_pubkey_xonly_tweak_add(mp_obj_t keyagg_cache_in, mp_obj_t tweak32_in){

    if(mp_obj_get_type(keyagg_cache_in) != &s_musig_keyagg_cache_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("key aggregation cache type"));
    }

    mp_obj_musig_keyagg_cache_t *cache = MP_OBJ_TO_PTR(keyagg_cache_in);

    mp_buffer_info_t tweak32;
    mp_get_buffer_raise(tweak32_in, &tweak32, MP_BUFFER_READ);
    if(tweak32.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("tweak32 len != 32"));
    }

    mp_obj_pubkey_t *res = m_new_obj(mp_obj_pubkey_t);
    res->base.type = &s_pubkey_type;

    int ok = secp256k1_musig_pubkey_xonly_tweak_add(secp256k1_context_static, &res->pubkey,
                                                    &cache->keyagg_cache, tweak32.buf);
    if (!ok){
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_pubkey_xonly_tweak_add invalid arguments"));
    }

    return MP_OBJ_FROM_PTR(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_musig_pubkey_xonly_tweak_add_obj, s_musig_pubkey_xonly_tweak_add);


STATIC mp_obj_t s_musig_nonce_gen(size_t n_args, const mp_obj_t *pos_args, mp_map_t *kw_args) {

	STATIC const mp_arg_t allowed_args[] = {
        { MP_QSTR_pubkey,         MP_ARG_REQUIRED | MP_ARG_OBJ, {.u_obj = MP_OBJ_NULL}   },
        { MP_QSTR_secrand,                          MP_ARG_OBJ, {.u_obj = mp_const_none} },
        { MP_QSTR_seckey,                           MP_ARG_OBJ, {.u_obj = mp_const_none} },
        { MP_QSTR_msg32,                            MP_ARG_OBJ, {.u_obj = mp_const_none} },
        { MP_QSTR_keyagg_cache,                     MP_ARG_OBJ, {.u_obj = mp_const_none} },
        { MP_QSTR_extra32,                          MP_ARG_OBJ, {.u_obj = mp_const_none} },
    };

    // parse args
    mp_arg_val_t args[MP_ARRAY_SIZE(allowed_args)];
    mp_arg_parse_all(n_args, pos_args, kw_args, MP_ARRAY_SIZE(allowed_args), allowed_args, args);

    // 1st & only required argument - pubkey
    if(mp_obj_get_type(args[0].u_obj) != &s_pubkey_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("pubkey type"));
    }
    mp_obj_pubkey_t *pk = MP_OBJ_TO_PTR(args[0].u_obj);

    // 2nd arg - optional - session secrand
    // must not be reused
    // buffer is invalidated upon successful execution of this function
    uint8_t session_secrand[32];
    if (args[1].u_obj != mp_const_none) {
        mp_buffer_info_t secrand;
        mp_get_buffer_raise(args[1].u_obj, &secrand, MP_BUFFER_READ);
        if(secrand.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("session secrand len != 32"));
        }
        memcpy(session_secrand, (uint8_t *)secrand.buf, 32);
    } else {
	    my_random_bytes(session_secrand, 32);
	}

    // 3rd arg - optional - seckey
    uint8_t *seckey = NULL;
    uint8_t seckey_buf[32];
    if (args[2].u_obj != mp_const_none) {
        mp_buffer_info_t sk;
        mp_get_buffer_raise(args[2].u_obj, &sk, MP_BUFFER_READ);
        if(sk.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("seckey len != 32"));
        }
        memcpy(seckey_buf, (uint8_t *)sk.buf, 32);
        seckey = seckey_buf;
    }

    // 4th - optional - msg32
    uint8_t *msg32 = NULL;
    uint8_t msg_buf[32];
    if (args[3].u_obj != mp_const_none) {
        mp_buffer_info_t msg;
        mp_get_buffer_raise(args[3].u_obj, &msg, MP_BUFFER_READ);
        if(msg.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("msg len != 32"));
        }
        memcpy(msg_buf, (uint8_t *)msg.buf, 32);
        msg32 = msg_buf;
    }

	// 5th arg - optional - key aggregation cache
    secp256k1_musig_keyagg_cache *keyagg_cache_ptr = NULL;
    if (args[4].u_obj != mp_const_none) {
        if(mp_obj_get_type(args[4].u_obj) != &s_musig_keyagg_cache_type) {
            mp_raise_TypeError(MP_ERROR_TEXT("key aggregation cache type"));
        }
        mp_obj_musig_keyagg_cache_t *cache = MP_OBJ_TO_PTR(args[4].u_obj);
        keyagg_cache_ptr = &cache->keyagg_cache;
    }

    // 6th - optional - extra input32
    uint8_t *extra_input32 = NULL;
    uint8_t extra32_buf[32];
    if (args[5].u_obj != mp_const_none) {
        mp_buffer_info_t extra32;
        mp_get_buffer_raise(args[5].u_obj, &extra32, MP_BUFFER_READ);
        if(extra32.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("extra input len != 32"));
        }
        memcpy(extra32_buf, (uint8_t *)extra32.buf, 32);
        extra_input32 = extra32_buf;
    }

	// new nonce produced by this function
	// musig pubnonce
	mp_obj_musig_secnonce_t *sn = m_new_obj(mp_obj_musig_secnonce_t);
	sn->base.type = &s_musig_secnonce_type;
	// musig secnonce
	mp_obj_musig_pubnonce_t *pn = m_new_obj(mp_obj_musig_pubnonce_t);
    pn->base.type = &s_musig_pubnonce_type;

	sec_setup_ctx();

    int ok = secp256k1_musig_nonce_gen(lib_ctx, &sn->secnonce, &pn->pubnonce, session_secrand, seckey,
                                       &pk->pubkey, msg32, keyagg_cache_ptr, extra_input32);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_nonce_gen"));
    }
    mp_obj_t res[2];
    res[0] = MP_OBJ_FROM_PTR(sn);
    res[1] = MP_OBJ_FROM_PTR(pn);
    return mp_obj_new_tuple(2, res);
}
MP_DEFINE_CONST_FUN_OBJ_KW(s_musig_nonce_gen_obj, 1, s_musig_nonce_gen);


STATIC mp_obj_t s_pubnonce_to_bytes(mp_obj_t pubnonce_in) {
    mp_obj_musig_pubnonce_t *self = MP_OBJ_TO_PTR(pubnonce_in);

    vstr_t vstr;
    vstr_init_len(&vstr, 66);

    secp256k1_musig_pubnonce_serialize(secp256k1_context_static, (uint8_t *)vstr.buf, &self->pubnonce);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_pubnonce_to_bytes_obj, s_pubnonce_to_bytes);


// Constructor for pubnonce
STATIC mp_obj_t s_pubnonce_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_musig_pubnonce_t *self = m_new_obj(mp_obj_musig_pubnonce_t);
    self->base.type = type;

    mp_buffer_info_t pubnonce66;
    mp_get_buffer_raise(args[0], &pubnonce66, MP_BUFFER_READ);
    if(pubnonce66.len != 66) {
        mp_raise_ValueError(MP_ERROR_TEXT("musig pubnonce len != 66"));
    }

    int ok = secp256k1_musig_pubnonce_parse(secp256k1_context_static, &self->pubnonce, pubnonce66.buf);

    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_pubnonce_parse"));
    }

    return MP_OBJ_FROM_PTR(self);
}


STATIC mp_obj_t s_aggnonce_to_bytes(mp_obj_t aggnonce_in) {
    mp_obj_musig_aggnonce_t *self = MP_OBJ_TO_PTR(aggnonce_in);

    vstr_t vstr;
    vstr_init_len(&vstr, 66);

    secp256k1_musig_aggnonce_serialize(secp256k1_context_static, (uint8_t *)vstr.buf, &self->aggnonce);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_aggnonce_to_bytes_obj, s_aggnonce_to_bytes);


// Constructor for aggregate nonce
STATIC mp_obj_t s_aggnonce_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_musig_aggnonce_t *self = m_new_obj(mp_obj_musig_aggnonce_t);
    self->base.type = type;

    mp_buffer_info_t aggnonce66;
    mp_get_buffer_raise(args[0], &aggnonce66, MP_BUFFER_READ);
    if(aggnonce66.len != 66) {
        mp_raise_ValueError(MP_ERROR_TEXT("musig aggnonce len != 66"));
    }

    int ok = secp256k1_musig_aggnonce_parse(secp256k1_context_static, &self->aggnonce, aggnonce66.buf);

    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_pubnonce_parse"));
    }

    return MP_OBJ_FROM_PTR(self);
}


STATIC mp_obj_t s_musig_nonce_agg(mp_obj_t pubnonces_in){
    if (!mp_obj_is_type(pubnonces_in, &mp_type_list)) {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected a list object"));
    }
    mp_obj_list_t *pubnonces = MP_OBJ_TO_PTR(pubnonces_in);

    size_t len_pubnonces = pubnonces->len;
    if (!len_pubnonces){
        mp_raise_ValueError(MP_ERROR_TEXT("Empty pubnonces list"));
    }

    // remap to secp array of pointers
    const secp256k1_musig_pubnonce *pns[len_pubnonces];
    for (size_t i = 0; i < len_pubnonces; i++) {
        if(mp_obj_get_type(pubnonces->items[i]) != &s_musig_pubnonce_type) {
            mp_raise_TypeError(MP_ERROR_TEXT("pubnonces: pubnonce type"));
        }
        mp_obj_musig_pubnonce_t *o = pubnonces->items[i];
        pns[i] = &o->pubnonce;
    }

    mp_obj_musig_aggnonce_t *an = m_new_obj(mp_obj_musig_aggnonce_t);
	an->base.type = &s_musig_aggnonce_type;

    int ok = secp256k1_musig_nonce_agg(secp256k1_context_static, &an->aggnonce, pns, len_pubnonces);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_nonce_agg"));
    }

    return MP_OBJ_FROM_PTR(an);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_musig_nonce_agg_obj, s_musig_nonce_agg);


STATIC mp_obj_t s_musig_nonce_process(mp_obj_t aggnonce_in, mp_obj_t msg32_in, mp_obj_t keyagg_cache_in){

    if(mp_obj_get_type(aggnonce_in) != &s_musig_aggnonce_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("aggnonce type"));
    }

    if(mp_obj_get_type(keyagg_cache_in) != &s_musig_keyagg_cache_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("key aggregation cache type"));
    }

    mp_obj_musig_aggnonce_t *an = MP_OBJ_TO_PTR(aggnonce_in);

    mp_buffer_info_t msg32;
    mp_get_buffer_raise(msg32_in, &msg32, MP_BUFFER_READ);
    if(msg32.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("msg len != 32"));
    }

    mp_obj_musig_keyagg_cache_t *cache = MP_OBJ_TO_PTR(keyagg_cache_in);

    // create musig session
    mp_obj_musig_session_t *session = m_new_obj(mp_obj_musig_session_t);
    session->base.type = &s_musig_session_type;

    int ok = secp256k1_musig_nonce_process(secp256k1_context_static, &session->session, &an->aggnonce,
                                           msg32.buf, &cache->keyagg_cache);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_nonce_process invalid arguments"));
    }

    return MP_OBJ_FROM_PTR(session);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_musig_nonce_process_obj, s_musig_nonce_process);


// Constructor for musig partial signature
STATIC mp_obj_t s_musig_partial_sig_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_musig_partial_sig_t *self = m_new_obj(mp_obj_musig_partial_sig_t);
    self->base.type = type;

    mp_buffer_info_t part_sig32;
    mp_get_buffer_raise(args[0], &part_sig32, MP_BUFFER_READ);
    if(part_sig32.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("musig partial signature len != 32"));
    }

    int ok = secp256k1_musig_partial_sig_parse(secp256k1_context_static, &self->sig, part_sig32.buf);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_partial_sig_parse"));
    }

    return MP_OBJ_FROM_PTR(self);
}

STATIC mp_obj_t s_musig_partial_sig_to_bytes(mp_obj_t part_sig_in) {
    mp_obj_musig_partial_sig_t *self = MP_OBJ_TO_PTR(part_sig_in);

    vstr_t vstr;
    vstr_init_len(&vstr, 32);

    secp256k1_musig_partial_sig_serialize(secp256k1_context_static, (uint8_t *)vstr.buf, &self->sig);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_musig_partial_sig_to_bytes_obj, s_musig_partial_sig_to_bytes);


STATIC mp_obj_t s_musig_partial_sign(size_t n_args, const mp_obj_t *args){

    if(mp_obj_get_type(args[0]) != &s_musig_secnonce_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("secnonce type"));
    }

    if(mp_obj_get_type(args[1]) != &s_keypair_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("keypair type"));
    }

    if(mp_obj_get_type(args[2]) != &s_musig_keyagg_cache_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("key aggregation cache type"));
    }

    if(mp_obj_get_type(args[3]) != &s_musig_session_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("session type"));
    }

    mp_obj_musig_secnonce_t *secnonce = MP_OBJ_TO_PTR(args[0]);
    mp_obj_keypair_t *keypair = MP_OBJ_TO_PTR(args[1]);
    mp_obj_musig_keyagg_cache_t *cache = MP_OBJ_TO_PTR(args[2]);
    mp_obj_musig_session_t *session = MP_OBJ_TO_PTR(args[3]);

    // new musig partial signature
    mp_obj_musig_partial_sig_t *res = m_new_obj(mp_obj_musig_partial_sig_t);
    res->base.type = &s_musig_partial_sig_type;

    sec_setup_ctx();

    int ok = secp256k1_musig_partial_sign(lib_ctx, &res->sig, &secnonce->secnonce, &keypair->keypair,
                                          &cache->keyagg_cache, &session->session);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_partial_sign invalid arguments or secnonce reuse"));
    }

    return MP_OBJ_FROM_PTR(res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_musig_partial_sign_obj, 4, 4, s_musig_partial_sign);


// verify musig partial sig
STATIC mp_obj_t s_musig_partial_sig_verify(size_t n_args, const mp_obj_t *args)
{
    // no need to verify partial sig type as it this is method of the object
    if(mp_obj_get_type(args[1]) != &s_musig_pubnonce_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("pubnonce type"));
    }

    if(mp_obj_get_type(args[2]) != &s_pubkey_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("pubkey type"));
    }

    if(mp_obj_get_type(args[3]) != &s_musig_keyagg_cache_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("key aggregation cache type"));
    }

    if(mp_obj_get_type(args[4]) != &s_musig_session_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("session type"));
    }

    mp_obj_musig_partial_sig_t *self = MP_OBJ_TO_PTR(args[0]);
    mp_obj_musig_pubnonce_t *pubnonce = MP_OBJ_TO_PTR(args[1]);
    mp_obj_pubkey_t *pubkey = MP_OBJ_TO_PTR(args[2]);
    mp_obj_musig_keyagg_cache_t *cache = MP_OBJ_TO_PTR(args[3]);
    mp_obj_musig_session_t *session = MP_OBJ_TO_PTR(args[4]);

    int ok = secp256k1_musig_partial_sig_verify(lib_ctx, &self->sig, &pubnonce->pubnonce, &pubkey->pubkey,
                                                &cache->keyagg_cache, &session->session);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_partial_sig_verify"));
    }

    return mp_obj_new_int(ok);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_musig_partial_sig_verify_obj, 5, 5, s_musig_partial_sig_verify);


STATIC mp_obj_t s_musig_partial_sig_agg(mp_obj_t part_sigs_in, mp_obj_t session_in){

    if (!mp_obj_is_type(part_sigs_in, &mp_type_list)) {
        mp_raise_TypeError(MP_ERROR_TEXT("Expected a list object"));
    }
    mp_obj_list_t *part_sigs = MP_OBJ_TO_PTR(part_sigs_in);

    size_t len_part_sigs = part_sigs->len;
    if (!len_part_sigs){
        mp_raise_ValueError(MP_ERROR_TEXT("Empty partial sigs list"));
    }

    // remap to secp array of pointers
    const secp256k1_musig_partial_sig *ps[len_part_sigs];
    for (size_t i = 0; i < len_part_sigs; i++) {
        if(mp_obj_get_type(part_sigs->items[i]) != &s_musig_partial_sig_type) {
            mp_raise_TypeError(MP_ERROR_TEXT("part_sigs: part sig type"));
        }
        mp_obj_musig_partial_sig_t *o = part_sigs->items[i];
        ps[i] = &o->sig;
    }

    if(mp_obj_get_type(session_in) != &s_musig_session_type) {
        mp_raise_TypeError(MP_ERROR_TEXT("session type"));
    }

    mp_obj_musig_session_t *session = MP_OBJ_TO_PTR(session_in);

    vstr_t res;
    vstr_init_len(&res, 64);

    int ok = secp256k1_musig_partial_sig_agg(lib_ctx, (uint8_t *)res.buf, &session->session, ps, len_part_sigs);
    if (!ok) {
        mp_raise_ValueError(MP_ERROR_TEXT("secp256k1_musig_partial_sig_agg invalid arguments"));
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &res);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_musig_partial_sig_agg_obj, s_musig_partial_sig_agg);


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

// musig partial signature
STATIC const mp_rom_map_elem_t s_musig_partial_sig_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_musig_partial_sig_to_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&s_musig_partial_sig_verify_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_musig_partial_sig_locals_dict, s_musig_partial_sig_locals_dict_table);

STATIC const mp_obj_type_t s_musig_partial_sig_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_musig_partial_sig,
    .make_new = s_musig_partial_sig_make_new,
    .locals_dict = (void *)&s_musig_partial_sig_locals_dict,
};

// pubkeys and what you can do with them
STATIC const mp_rom_map_elem_t s_pubkey_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_pubkey_to_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_to_xonly), MP_ROM_PTR(&s_pubkey_to_xonly_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_pubkey_locals_dict, s_pubkey_locals_dict_table);

STATIC const mp_rom_map_elem_t s_xonly_pubkey_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_xonly_pubkey_to_bytes_obj) },
    { MP_ROM_QSTR(MP_QSTR_parity), MP_ROM_PTR(&s_xonly_pubkey_parity_obj) },
    { MP_ROM_QSTR(MP_QSTR_tweak_add), MP_ROM_PTR(&s_xonly_pubkey_tweak_add_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_xonly_pubkey_locals_dict, s_xonly_pubkey_locals_dict_table);

STATIC const mp_obj_type_t s_pubkey_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_pubkey,
    .make_new = s_pubkey_make_new,
    .locals_dict = (void *)&s_pubkey_locals_dict,
};

STATIC const mp_obj_type_t s_xonly_pubkey_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_xonly_pubkey,
    .make_new = s_xonly_pubkey_make_new,
    .locals_dict = (void *)&s_xonly_pubkey_locals_dict,
};

// musig opaque
STATIC const mp_obj_type_t s_musig_session_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_musig_session,
};

STATIC const mp_rom_map_elem_t s_musig_keyagg_cache_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_agg_pubkey), MP_ROM_PTR(&s_musig_pubkey_get_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_musig_keyagg_cache_locals_dict, s_musig_keyagg_cache_locals_dict_table);

STATIC const mp_obj_type_t s_musig_keyagg_cache_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_musig_keyagg_cache,
    .make_new = s_musig_keyagg_cache_make_new,
    .locals_dict = (void *)&s_musig_keyagg_cache_locals_dict,
};

// musig nonces
STATIC const mp_rom_map_elem_t s_musig_pubnonce_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_pubnonce_to_bytes_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_musig_pubnonce_locals_dict, s_musig_pubnonce_locals_dict_table);

STATIC const mp_obj_type_t s_musig_pubnonce_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_musig_pubnonce,
    .make_new = s_pubnonce_make_new,
    .locals_dict = (void *)&s_musig_pubnonce_locals_dict,
};

STATIC const mp_rom_map_elem_t s_musig_aggnonce_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_to_bytes), MP_ROM_PTR(&s_aggnonce_to_bytes_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_musig_aggnonce_locals_dict, s_musig_aggnonce_locals_dict_table);

STATIC const mp_obj_type_t s_musig_aggnonce_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_musig_aggnonce,
    .make_new = s_aggnonce_make_new,
    .locals_dict = (void *)&s_musig_aggnonce_locals_dict,
};

STATIC const mp_obj_type_t s_musig_secnonce_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_musig_secnonce,
};

// privkeys and what you can do with them
STATIC const mp_rom_map_elem_t s_keypair_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_privkey), MP_ROM_PTR(&s_keypair_privkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_keypair_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_xonly_pubkey), MP_ROM_PTR(&s_keypair_xonly_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_xonly_tweak_add), MP_ROM_PTR(&s_keypair_xonly_tweak_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_ecdh_multiply), MP_ROM_PTR(&s_keypair_ecdh_multiply_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_keypair_locals_dict, s_keypair_locals_dict_table);

STATIC const mp_obj_type_t s_keypair_type = {
    { &mp_type_type },
    .name = MP_QSTR_secp256k1_keypair,
    .make_new = s_keypair_make_new,
    .locals_dict = (void *)&s_keypair_locals_dict,
};


STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_secp256k1) },

    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_pubkey_type) },
    { MP_ROM_QSTR(MP_QSTR_xonly_pubkey), MP_ROM_PTR(&s_xonly_pubkey_type) },
    { MP_ROM_QSTR(MP_QSTR_keypair), MP_ROM_PTR(&s_keypair_type) },
    { MP_ROM_QSTR(MP_QSTR_signature), MP_ROM_PTR(&s_sig_type) },
    { MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&s_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_sign_schnorr), MP_ROM_PTR(&s_sign_schnorr_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify_schnorr), MP_ROM_PTR(&s_verify_schnorr_obj) },
    { MP_ROM_QSTR(MP_QSTR_ctx_rnd), MP_ROM_PTR(&s_ctx_rnd_obj) },

    { MP_ROM_QSTR(MP_QSTR_MusigKeyAggCache), MP_ROM_PTR(&s_musig_keyagg_cache_type) },
    { MP_ROM_QSTR(MP_QSTR_musig_nonce_gen), MP_ROM_PTR(&s_musig_nonce_gen_obj) },
    { MP_ROM_QSTR(MP_QSTR_MusigPubNonce), MP_ROM_PTR(&s_musig_pubnonce_type) },
    { MP_ROM_QSTR(MP_QSTR_musig_nonce_agg), MP_ROM_PTR(&s_musig_nonce_agg_obj) },
    { MP_ROM_QSTR(MP_QSTR_MusigAggNonce), MP_ROM_PTR(&s_musig_aggnonce_type) },
    { MP_ROM_QSTR(MP_QSTR_MusigPartSig), MP_ROM_PTR(&s_musig_partial_sig_type) },
    { MP_ROM_QSTR(MP_QSTR_musig_pubkey_agg), MP_ROM_PTR(&s_musig_pubkey_agg_obj) },
    { MP_ROM_QSTR(MP_QSTR_musig_pubkey_ec_tweak_add), MP_ROM_PTR(&s_musig_pubkey_ec_tweak_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_musig_pubkey_xonly_tweak_add), MP_ROM_PTR(&s_musig_pubkey_xonly_tweak_add_obj) },
    { MP_ROM_QSTR(MP_QSTR_musig_nonce_process), MP_ROM_PTR(&s_musig_nonce_process_obj) },
    { MP_ROM_QSTR(MP_QSTR_musig_partial_sign), MP_ROM_PTR(&s_musig_partial_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_musig_partial_sig_agg), MP_ROM_PTR(&s_musig_partial_sig_agg_obj) },
};

STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_secp256k1 = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};

