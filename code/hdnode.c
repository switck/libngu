// 
// hdnode - BIP32 HD keys
//
//
#include "py/runtime.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "my_assert.h"

#include "sec_shared.h"
#include "libbase58.h"
#include "mbedtls/md.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha256.h"

typedef struct  {
    mp_obj_base_t       base;
    uint8_t             privkey[32];
    uint8_t             pubkey[33];
    int                 depth;
    uint32_t            child_num;
    uint32_t            parent_fp;
    uint8_t             chain_code[32];
    bool                have_private;
    bool                have_public;
} mp_obj_hdnode_t;

STATIC const mp_obj_type_t s_hdnode_type;

typedef union {
    struct {
        uint8_t     left[32];
        uint8_t     right[32];
    } lr;
    uint8_t     both[64];
} left_right_t;

void hmac_sha512(const uint8_t *key, uint32_t key_len,
                    const uint8_t *data, uint32_t data_len,
                    left_right_t *result)
{
    STATIC_ASSERT(sizeof(left_right_t) == 64);
    const mbedtls_md_info_t *md_algo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    int rv = mbedtls_md_hmac(md_algo, key, key_len, data, data_len, result->both);
    assert(rv == 0);
}

static inline uint8_t *write_be32(uint8_t *p, uint32_t v)
{
    *(p++) = v >> 24;
    *(p++) = v >> 16;
    *(p++) = v >> 8;
    *(p++) = v & 0xff;

    return p;
}

static inline uint32_t read_be32(uint8_t **p)
{
    uint8_t *v = (*p);
    (*p) += 4;
    return (v[0] << 24) | (v[1] << 16) | (v[2] << 8) | v[3];
}

void _calc_pubkey(mp_obj_hdnode_t *self)
{
    // calc based on privkey
    assert(self->have_private);

    sec_setup_ctx();

    secp256k1_pubkey    pub;
    int rv = secp256k1_ec_pubkey_create(lib_ctx, &pub, self->privkey);

    if(!rv) mp_raise_msg(&mp_type_RuntimeError, NULL);

    size_t outlen = sizeof(self->pubkey);
    rv = secp256k1_ec_pubkey_serialize(lib_ctx,
            self->pubkey, &outlen,
            &pub, SECP256K1_EC_COMPRESSED);

    if(!rv) mp_raise_msg(&mp_type_RuntimeError, NULL);
    assert(outlen == sizeof(self->pubkey));

    self->have_public = true;
}

uint32_t _calc_my_fp(mp_obj_hdnode_t *self)
{
    if(!self->have_public) {
        _calc_pubkey(self);
    }

    uint8_t tmp[32];

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, self->pubkey, 33);
    mbedtls_sha256_finish_ret(&ctx, tmp);
    mbedtls_sha256_free(&ctx);
    
    mbedtls_ripemd160_context    r_ctx;
    mbedtls_ripemd160_init(&r_ctx);
    mbedtls_ripemd160_starts_ret(&r_ctx);
    mbedtls_ripemd160_update_ret(&r_ctx, tmp, 32);
    mbedtls_ripemd160_finish_ret(&r_ctx, tmp);
    mbedtls_ripemd160_free(&r_ctx);

    uint8_t *p = tmp;
    return read_be32(&p);
}

// Constructor: makes empty/invalid obj
STATIC mp_obj_t s_hdnode_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_obj_hdnode_t *o = m_new_obj(mp_obj_hdnode_t);

    memset(o, 0, sizeof(mp_obj_hdnode_t));
    o->base.type = type;

    o->depth = -1;          // mark invalid

    return MP_OBJ_FROM_PTR(o);
}


// METHODS

STATIC mp_obj_t s_hdnode_privkey(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    vstr_t vstr;
    vstr_init_len(&vstr, 32);

    if(!self->have_private) {
        mp_raise_ValueError(MP_ERROR_TEXT("no privkey"));
    }
    memcpy(vstr.buf, self->privkey, 32);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_privkey_obj, s_hdnode_privkey);

STATIC mp_obj_t s_hdnode_pubkey(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    vstr_t vstr;
    vstr_init_len(&vstr, 33);

    // 33 bytes of pubkey
    if(!self->have_public) {
        _calc_pubkey(self);
    }
    memcpy(vstr.buf, self->pubkey, sizeof(self->pubkey));

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_pubkey_obj, s_hdnode_pubkey);

STATIC mp_obj_t s_hdnode_serialize(mp_obj_t self_in, mp_obj_t version_in, mp_obj_t want_private_in) {
    // output BIP32 bytes
    //  version bytes: uint32 w/ first 4 bytes (giving xpub/Zpub/etc)
    //  private: flag, exporting private key else public part
    // result is base58 bytes
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    uint32_t version = mp_obj_get_int(version_in);
    bool want_private = !!mp_obj_get_int_truncated(want_private_in);

    uint8_t     out[78], *p=out;

    p = write_be32(p, version);
    *(p++) = self->depth;
    p = write_be32(p, self->parent_fp);
    p = write_be32(p, self->child_num);
    memcpy(p, self->chain_code, 32);
    p += 32;
    
    if(want_private) {
        if(!self->have_private) {
            mp_raise_ValueError(MP_ERROR_TEXT("no privkey"));
        }

        *(p++) = 0;
        memcpy(p, self->privkey, 32);
        p += 32;
    } else {
        // 33 bytes of pubkey
        if(!self->have_public) {
            _calc_pubkey(self);
        }

        assert(self->have_public);
        memcpy(p, self->pubkey, 33);
        p += 33;
    }

    assert(p == out+sizeof(out));

/*
printf("out = ");
for(int i=0; i<78; i++) printf("%02x", out[i]);
printf("\n");
*/

    char tmp[150];      // max 111 based on 78 bytes in

    int len_out = base58_encode_check(out, sizeof(out), tmp, sizeof(tmp));
    if(len_out <= 0) {
        mp_raise_ValueError(NULL);
    }

    return mp_obj_new_str(tmp, len_out-1);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_hdnode_serialize_obj, s_hdnode_serialize);

STATIC mp_obj_t s_hdnode_deserialize(mp_obj_t self_in, mp_obj_t encoded) {
    // deserialize into self, works from base58; returns version
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    uint8_t tmp[120], *p = tmp;
    int len_out = base58_decode_check(mp_obj_str_get_str(encoded), tmp, sizeof(tmp));
    if(len_out <= 0) {
        mp_raise_ValueError(MP_ERROR_TEXT("encoding error"));
    }
    if(len_out != 78) {
        mp_raise_ValueError(MP_ERROR_TEXT("bad len"));
    }

    self->depth = -1;

    uint32_t version = read_be32(&p);
    self->depth = *(p++);
    self->parent_fp = read_be32(&p);
    self->child_num = read_be32(&p);

    memcpy(self->chain_code, p, 32);
    p += 32;
    
    if(p[0] == 0x00) {
        p++;
        memcpy(self->privkey, p, 32);
        p += 32;
        self->have_private = true;
        self->have_public = false;      // but could calc it
    } else if(p[0] == 0x02 || p[0] == 0x3) {
        // 33 bytes of pubkey
        self->have_private = false;
        self->have_public = true;
        memcpy(self->pubkey, p, 33);
        p += 33;
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("bad pubkey"));
    }

    assert(p == &tmp[78]);

    return mp_obj_new_int(version);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_hdnode_deserialize_obj, s_hdnode_deserialize);

STATIC mp_obj_t s_hdnode_from_master(mp_obj_t self_in, mp_obj_t master_secret_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    mp_buffer_info_t buf;
    mp_get_buffer_raise(master_secret_in, &buf, MP_BUFFER_READ);
    // check len >= 32? meh; not our problem

    left_right_t I;
    hmac_sha512((const uint8_t *)"Bitcoin seed", 12, buf.buf, buf.len, &I);

    memcpy(self->privkey, I.lr.left, 32);
    memcpy(self->chain_code, I.lr.right, 32);
    self->depth = 0;
    self->child_num = 0;
    self->have_private = true; 
    self->have_public = false;
    self->parent_fp = 0;

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_hdnode_from_master_obj, s_hdnode_from_master);


STATIC mp_obj_t s_hdnode_derive(mp_obj_t self_in, mp_obj_t next_child_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    uint32_t next_child = mp_obj_get_int(next_child_in);
    uint32_t parent_fp = _calc_my_fp(self);

    bool hard = !!(next_child & 0x80000000);

    sec_setup_ctx();

    if(hard && !self->have_private) {
        mp_raise_TypeError(MP_ERROR_TEXT("hard deriv on pub"));
    }

    // need public key in all cases
    if(!self->have_public) {
        _calc_pubkey(self);
    }

    // food for HMAC-SHA512
    uint8_t     work[33+4], *p=work;
    if(self->have_private) {
        *(p++) = 0x0;
        memcpy(p, self->privkey, 32); p += 32;
    } else {
        memcpy(p, self->pubkey, 33); p += 33;
    }
    p = write_be32(p, next_child);
    assert(p == &work[sizeof(work)]);
            
    left_right_t I;
    hmac_sha512(self->chain_code, 32, work, sizeof(work), &I);

    int ok;
    if(self->have_private) {
        // Ileft + k(mod n)
        ok = secp256k1_ec_privkey_tweak_add(lib_ctx, I.lr.left, self->privkey);
        if(!ok) goto fail;

        if(!hard) {
            _calc_pubkey(self);
        } else {
            self->have_public = false;
        }
    } else {
        secp256k1_pubkey        pub;

        ok = secp256k1_ec_pubkey_parse(lib_ctx, &pub, self->pubkey, 33);
        if(!ok) goto fail;

        ok = secp256k1_ec_pubkey_tweak_add(lib_ctx, &pub, I.lr.left);
        if(!ok) goto fail;

        size_t outlen = sizeof(self->pubkey);
        ok = secp256k1_ec_pubkey_serialize(lib_ctx, self->pubkey, &outlen,
                                                    &pub, SECP256K1_EC_COMPRESSED);
        if(!ok) goto fail;
        assert(outlen == 33);

        self->have_public = true;
    }

    if(!hard) {
        self->have_private = false;
        memset(self->privkey, 0, 32);
    }

    memcpy(self->chain_code, I.lr.right, 32);
    self->depth += 1;
    self->child_num = next_child;
    self->parent_fp = parent_fp;

    return self_in;

fail:
    self->depth = -1;
    mp_raise_ValueError(MP_ERROR_TEXT("bip32 lottery won"));
    return 0;       // not reached
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_hdnode_derive_obj, s_hdnode_derive);

// Accessors

STATIC mp_obj_t s_hdnode_depth(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    return MP_OBJ_NEW_SMALL_INT(self->depth);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_depth_obj, s_hdnode_depth);

STATIC mp_obj_t s_hdnode_parent_fp(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    return mp_obj_new_int(self->parent_fp);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_parent_fp_obj, s_hdnode_parent_fp);

STATIC mp_obj_t s_hdnode_my_fp(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    uint32_t rv = _calc_my_fp(self);

    return mp_obj_new_int(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_my_fp_obj, s_hdnode_my_fp);

STATIC mp_obj_t s_hdnode_child_number(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    return mp_obj_new_int(self->child_num);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_child_number_obj, s_hdnode_child_number);


// member vars
STATIC const mp_rom_map_elem_t s_hdnode_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_privkey), MP_ROM_PTR(&s_hdnode_privkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_hdnode_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_serialize), MP_ROM_PTR(&s_hdnode_serialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_deserialize), MP_ROM_PTR(&s_hdnode_deserialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_from_master), MP_ROM_PTR(&s_hdnode_from_master_obj) },
    { MP_ROM_QSTR(MP_QSTR_derive), MP_ROM_PTR(&s_hdnode_derive_obj) },

    { MP_ROM_QSTR(MP_QSTR_depth), MP_ROM_PTR(&s_hdnode_depth_obj) },
    { MP_ROM_QSTR(MP_QSTR_child_number), MP_ROM_PTR(&s_hdnode_child_number_obj) },
    { MP_ROM_QSTR(MP_QSTR_parent_fp), MP_ROM_PTR(&s_hdnode_parent_fp_obj) },
    { MP_ROM_QSTR(MP_QSTR_my_fp), MP_ROM_PTR(&s_hdnode_my_fp_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_hdnode_locals_dict, s_hdnode_locals_dict_table);

// class: HDNode
STATIC const mp_obj_type_t s_hdnode_type = {
    { &mp_type_type },
    .name = MP_QSTR_HDNode,
    .make_new = s_hdnode_make_new,
    .locals_dict = (void *)&s_hdnode_locals_dict,
};

STATIC const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hdnode) },

    { MP_ROM_QSTR(MP_QSTR_HDNode), MP_ROM_PTR(&s_hdnode_type) },

};
STATIC MP_DEFINE_CONST_DICT(globals_table_obj, globals_table);

const mp_obj_module_t mp_module_hdnode = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&globals_table_obj,
};
