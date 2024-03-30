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
#include "hash.h"

#define EXTRA_DEBUG

typedef struct  {
    mp_obj_base_t       base;
    uint8_t             chain_code[32];
    uint8_t             privkey[32];
    uint8_t             pubkey[33];
    uint8_t             hash160[20];
    int                 depth;
    uint32_t            child_num;
    uint32_t            parent_fp;
    bool                have_private;
#ifdef EXTRA_DEBUG
    char                path[40];       // debug aid
    uint32_t            root_fp;
#endif
} mp_obj_hdnode_t;

STATIC const mp_obj_type_t s_hdnode_type;

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

static inline void raise_on_invalid(mp_obj_hdnode_t *n)
{
    if(
        (n->depth < 0)
        || ((n->pubkey[0] != 0x02) && (n->pubkey[0] != 0x03))
    ) {
        mp_raise_msg(&mp_type_ValueError, MP_ERROR_TEXT("invalid HDNode"));
    }
}

static void _calc_pubkey(mp_obj_hdnode_t *self)
{
    // calc based on privkey
    assert(self->have_private);

    sec_setup_ctx();

    secp256k1_pubkey    pub;
    int rv = secp256k1_ec_pubkey_create(lib_ctx, &pub, self->privkey);
    if(!rv) mp_raise_msg(&mp_type_RuntimeError, MP_ERROR_TEXT("bip32 lottery winner"));

    size_t outlen = sizeof(self->pubkey);
    rv = secp256k1_ec_pubkey_serialize(lib_ctx,
            self->pubkey, &outlen,
            &pub, SECP256K1_EC_COMPRESSED);

    if(!rv) mp_raise_msg(&mp_type_RuntimeError, NULL);
    assert(outlen == sizeof(self->pubkey));
}


static inline void _calc_hash160(mp_obj_hdnode_t *self)
{
    hash160(self->pubkey, 33, self->hash160);
}

static uint32_t _calc_my_fp(mp_obj_hdnode_t *self)
{
    uint8_t *p = self->hash160;
    return read_be32(&p);
}

// Constructor: makes empty/invalid obj
STATIC mp_obj_t s_hdnode_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);
    mp_obj_hdnode_t *o = m_new_obj_with_finaliser(mp_obj_hdnode_t);

    memset(o, 0, sizeof(mp_obj_hdnode_t));
    o->base.type = type;

    o->depth = -1;          // mark invalid

    return MP_OBJ_FROM_PTR(o);
}


// METHODS
STATIC mp_obj_t s_hdnode_copy(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);         // debatable, but isolates faults faster

    mp_obj_hdnode_t *rv = m_new_obj_with_finaliser(mp_obj_hdnode_t);
    *rv = *self;
    rv->base.type = &s_hdnode_type;
    
    return rv;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_copy_obj, s_hdnode_copy);

STATIC mp_obj_t s_hdnode_blank(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    memset(self, 0, sizeof(mp_obj_hdnode_t));
    self->base.type = &s_hdnode_type;
    self->depth = -1;          // mark invalid
    
    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_blank_obj, s_hdnode_blank);

STATIC mp_obj_t s_hdnode_privkey(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

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
    raise_on_invalid(self);

    vstr_t vstr;
    vstr_init_len(&vstr, 33);

    // 33 bytes of pubkey
    memcpy(vstr.buf, self->pubkey, sizeof(self->pubkey));

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_pubkey_obj, s_hdnode_pubkey);

STATIC mp_obj_t s_hdnode_addr_help(size_t n_args, const mp_obj_t *args) {

    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(args[0]);
    raise_on_invalid(self);

    // ripemd160 over pubkey, but prefix with user-supplied value,
    // and then base58... or just just the ripemd part if no prefix given
    if(n_args < 2) {
        return mp_obj_new_bytes((uint8_t *)self->hash160, 20);
    }

    uint8_t     work[21];
    work[0] = mp_obj_get_int(args[1]);
    memcpy(&work[1], self->hash160, 20);

    char tmp[128];
    int len_out = base58_encode_check(work, 21, tmp, sizeof(tmp));
    if(len_out <= 0) {
        mp_raise_ValueError(NULL);
    }
    return mp_obj_new_str(tmp, len_out-1);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(s_hdnode_addr_help_obj, 1, 2, s_hdnode_addr_help);

STATIC mp_obj_t s_hdnode_serialize(mp_obj_t self_in, mp_obj_t version_in, mp_obj_t want_private_in) {
    // output BIP32 bytes
    //  version bytes: uint32 w/ first 4 bytes (giving xpub/Zpub/etc)
    //  private: flag, exporting private key else public part
    // result is base58 bytes
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

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
    // deserialize into self, works from base58; returns version observed
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
        _calc_pubkey(self);
    } else if(p[0] == 0x02 || p[0] == 0x3) {
        // 33 bytes of pubkey
        self->have_private = false;
        memcpy(self->pubkey, p, 33);
        p += 33;
    } else {
        mp_raise_ValueError(MP_ERROR_TEXT("bad pubkey"));
    }

    _calc_hash160(self);

#ifdef EXTRA_DEBUG
    self->path[0] = 0;
    self->root_fp = 0;
    if(self->depth) {
        snprintf(self->path, sizeof(self->path), "m/_/%d", (int)(self->child_num & 0x7fffffff));
        if( self->child_num & 0x80000000) {
            strcat(self->path, "'");
        }
    }
#endif

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
    self->parent_fp = 0;

#ifdef EXTRA_DEBUG
    self->path[0] = 0;
    self->root_fp = 0;
#endif

    _calc_pubkey(self);
    _calc_hash160(self);

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_hdnode_from_master_obj, s_hdnode_from_master);

STATIC mp_obj_t s_hdnode_from_chaincode_privkey(mp_obj_t self_in, mp_obj_t chain_code_in, mp_obj_t privkey_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    mp_buffer_info_t cc, pk;
    mp_get_buffer_raise(chain_code_in, &cc, MP_BUFFER_READ);
    mp_get_buffer_raise(privkey_in, &pk, MP_BUFFER_READ);

    if(cc.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("chaincode len"));
    }
    if(pk.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("privkey len"));
    }

    memcpy(self->privkey, pk.buf, 32);
    memcpy(self->chain_code, cc.buf, 32);
    self->depth = 0;
    self->child_num = 0;
    self->have_private = true; 
    self->parent_fp = 0;

#ifdef EXTRA_DEBUG
    self->path[0] = 0;
    self->root_fp = 0;
#endif

    _calc_pubkey(self);
    _calc_hash160(self);

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_hdnode_from_chaincode_privkey_obj, s_hdnode_from_chaincode_privkey);


STATIC mp_obj_t s_hdnode_censor(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    self->depth = 0;
    self->child_num = 0;
    self->parent_fp = 0;
#ifdef EXTRA_DEBUG
    self->path[0] = 0;
    self->root_fp = 0;
#endif

    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_censor_obj, s_hdnode_censor);


STATIC mp_obj_t s_hdnode_derive(mp_obj_t self_in, mp_obj_t next_child_in, mp_obj_t hard_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    uint32_t next_child = mp_obj_get_int(next_child_in);
    uint32_t parent_fp = _calc_my_fp(self);

    bool hard = !!mp_obj_get_int(hard_in);
    if(hard) next_child |= 0x80000000;

    sec_setup_ctx();

    if(hard && !self->have_private) {
        mp_raise_TypeError(MP_ERROR_TEXT("hard deriv on pubkey"));
    }

    // food for HMAC-SHA512
    uint8_t     work[33+4], *p=work;
    if(hard) {
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
        ok = secp256k1_ec_seckey_tweak_add(lib_ctx, self->privkey, I.lr.left);
        if(!ok) goto fail;

        _calc_pubkey(self);
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
    }

    memcpy(self->chain_code, I.lr.right, 32);
    self->depth += 1;
    self->child_num = next_child;
    self->parent_fp = parent_fp;

#ifdef EXTRA_DEBUG
    if(self->depth == 1) {
        self->root_fp = parent_fp;
    }
    if(strlen(self->path) >= sizeof(self->path)-12) {
        strcpy(self->path, "/_");
    }
    snprintf(self->path+strlen(self->path), sizeof(self->path)-strlen(self->path),
                        "/%d", (int)(next_child & 0x7fffffff));
    if(hard) {
        strcat(self->path, "'");
    }
#endif

    _calc_hash160(self);

    return self_in;

fail:
    self->depth = -1;
    mp_raise_ValueError(MP_ERROR_TEXT("bip32 lottery won"));
    return 0;       // not reached
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(s_hdnode_derive_obj, s_hdnode_derive);

// Accessors

STATIC mp_obj_t s_hdnode_depth(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    return MP_OBJ_NEW_SMALL_INT(self->depth);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_depth_obj, s_hdnode_depth);

STATIC mp_obj_t s_hdnode_parent_fp(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    return mp_obj_new_int_from_uint(self->parent_fp);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_parent_fp_obj, s_hdnode_parent_fp);

STATIC mp_obj_t s_hdnode_my_fp(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    uint32_t rv = _calc_my_fp(self);

    return mp_obj_new_int_from_uint(rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_my_fp_obj, s_hdnode_my_fp);

STATIC mp_obj_t s_hdnode_child_number(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    const mp_obj_t rv[2] = { 
        MP_OBJ_NEW_SMALL_INT(self->child_num & 0x7fffffff),
        (self->child_num & 0x80000000) ? mp_const_true : mp_const_false,
    };
    return mp_obj_new_tuple(2, rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_child_number_obj, s_hdnode_child_number);

STATIC mp_obj_t s_hdnode_chain_code(mp_obj_t self_in) {
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);
    raise_on_invalid(self);

    vstr_t vstr;
    vstr_init_len(&vstr, 32);
    memcpy(vstr.buf, self->chain_code, 32);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_hdnode_chain_code_obj, s_hdnode_chain_code);

#ifdef EXTRA_DEBUG
STATIC void s_hdnode_repr(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    (void)kind;
    mp_obj_hdnode_t *self = MP_OBJ_TO_PTR(self_in);

    if(self->depth < 0) {
        mp_printf(print, "<HDNode: invalid>");
    } else if(self->depth == 0) {
        mp_printf(print, "<HDNode: m=%02x%02x%02x%02x>",
            self->hash160[0], self->hash160[1], self->hash160[2], self->hash160[3]);
    } else {
        mp_printf(print, "<HDNode: (m=%02x%02x%02x%02x)%s>", 
            (self->root_fp >> 24) & 0xff, 
            (self->root_fp >> 16) & 0xff, 
            (self->root_fp >> 8) & 0xff, 
            self->root_fp & 0xff, self->path);
    }
}
#endif


// member vars
STATIC const mp_rom_map_elem_t s_hdnode_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_privkey), MP_ROM_PTR(&s_hdnode_privkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_pubkey), MP_ROM_PTR(&s_hdnode_pubkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_serialize), MP_ROM_PTR(&s_hdnode_serialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_deserialize), MP_ROM_PTR(&s_hdnode_deserialize_obj) },
    { MP_ROM_QSTR(MP_QSTR_from_master), MP_ROM_PTR(&s_hdnode_from_master_obj) },
    { MP_ROM_QSTR(MP_QSTR_from_chaincode_privkey), MP_ROM_PTR(&s_hdnode_from_chaincode_privkey_obj) },
    { MP_ROM_QSTR(MP_QSTR_derive), MP_ROM_PTR(&s_hdnode_derive_obj) },
    { MP_ROM_QSTR(MP_QSTR_addr_help), MP_ROM_PTR(&s_hdnode_addr_help_obj) },

    { MP_ROM_QSTR(MP_QSTR_depth), MP_ROM_PTR(&s_hdnode_depth_obj) },
    { MP_ROM_QSTR(MP_QSTR_child_number), MP_ROM_PTR(&s_hdnode_child_number_obj) },
    { MP_ROM_QSTR(MP_QSTR_parent_fp), MP_ROM_PTR(&s_hdnode_parent_fp_obj) },
    { MP_ROM_QSTR(MP_QSTR_my_fp), MP_ROM_PTR(&s_hdnode_my_fp_obj) },
    { MP_ROM_QSTR(MP_QSTR_chain_code), MP_ROM_PTR(&s_hdnode_chain_code_obj) },

    { MP_ROM_QSTR(MP_QSTR_copy), MP_ROM_PTR(&s_hdnode_copy_obj) },
    { MP_ROM_QSTR(MP_QSTR_censor), MP_ROM_PTR(&s_hdnode_censor_obj) },

    { MP_ROM_QSTR(MP_QSTR_blank), MP_ROM_PTR(&s_hdnode_blank_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&s_hdnode_blank_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_hdnode_locals_dict, s_hdnode_locals_dict_table);

// class: HDNode
STATIC const mp_obj_type_t s_hdnode_type = {
    { &mp_type_type },
    .name = MP_QSTR_HDNode,
    .make_new = s_hdnode_make_new,
#ifdef EXTRA_DEBUG
    .print = s_hdnode_repr,
#endif
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
