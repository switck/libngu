//
// hash.c - less common or special hashers
//
// - sha512
// - ripemd160
//
#include "py/runtime.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#if MICROPY_SSL_MBEDTLS
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha512.h"
#include "mbedtls/sha256.h"
#else
# error "requires MBEDTLS"
#endif

typedef struct _mp_obj_hash_t {
    mp_obj_base_t base;
    char state[0];
} mp_obj_hash_t;


//
// SHA512
//

STATIC mp_obj_t modngu_hash_sha512_update(mp_obj_t self_in, mp_obj_t arg);

STATIC mp_obj_t modngu_hash_sha512_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_hash_t *o = m_new_obj_var(mp_obj_hash_t, char, sizeof(mbedtls_sha512_context));
    o->base.type = type;

    mbedtls_sha512_init((mbedtls_sha512_context *)o->state);
    mbedtls_sha512_starts_ret((mbedtls_sha512_context *)o->state, false);

    if(n_args == 1) {
        modngu_hash_sha512_update(MP_OBJ_FROM_PTR(o), args[0]);
    }

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t modngu_hash_sha512_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    mp_buffer_info_t bufinfo;

    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    mbedtls_sha512_update_ret((mbedtls_sha512_context *)self->state, bufinfo.buf, bufinfo.len);

    return mp_const_none;
}

STATIC mp_obj_t modngu_hash_sha512_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);

    vstr_t vstr;
    vstr_init_len(&vstr, 64);

    mbedtls_sha512_finish_ret((mbedtls_sha512_context *)self->state, (byte *)vstr.buf);
    mbedtls_sha512_free((mbedtls_sha512_context *)self->state);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}

STATIC MP_DEFINE_CONST_FUN_OBJ_2(modngu_hash_sha512_update_obj, modngu_hash_sha512_update);
STATIC MP_DEFINE_CONST_FUN_OBJ_1(modngu_hash_sha512_digest_obj, modngu_hash_sha512_digest);

STATIC const mp_rom_map_elem_t modngu_hash_sha512_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&modngu_hash_sha512_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&modngu_hash_sha512_digest_obj) },
};
STATIC MP_DEFINE_CONST_DICT(modngu_hash_sha512_locals_dict, modngu_hash_sha512_locals_dict_table);

STATIC const mp_obj_type_t modngu_hash_sha512_type = {
    { &mp_type_type },
    .name = MP_QSTR_sha512,
    .make_new = modngu_hash_sha512_make_new,
    .locals_dict = (void *)&modngu_hash_sha512_locals_dict,
};

//
// RIPEMD160
//

STATIC mp_obj_t modngu_hash_ripemd160_update(mp_obj_t self_in, mp_obj_t arg);

STATIC mp_obj_t modngu_hash_ripemd160_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
    mp_obj_hash_t *o = m_new_obj_var(mp_obj_hash_t, char, sizeof(mbedtls_ripemd160_context));
    o->base.type = type;

    mbedtls_ripemd160_init((mbedtls_ripemd160_context *)o->state);
    mbedtls_ripemd160_starts_ret((mbedtls_ripemd160_context *)o->state);

    if(n_args == 1) {
        modngu_hash_ripemd160_update(MP_OBJ_FROM_PTR(o), args[0]);
    }

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t modngu_hash_ripemd160_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);
    mbedtls_ripemd160_update_ret((mbedtls_ripemd160_context *)self->state, bufinfo.buf, bufinfo.len);
    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(modngu_hash_ripemd160_update_obj, modngu_hash_ripemd160_update);

STATIC mp_obj_t modngu_hash_ripemd160_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    vstr_t vstr;
    vstr_init_len(&vstr, 20);

    mbedtls_ripemd160_finish_ret((mbedtls_ripemd160_context *)self->state, (byte *)vstr.buf);
    mbedtls_ripemd160_free((mbedtls_ripemd160_context *)self->state);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(modngu_hash_ripemd160_digest_obj, modngu_hash_ripemd160_digest);

STATIC const mp_rom_map_elem_t modngu_hash_ripemd160_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&modngu_hash_ripemd160_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&modngu_hash_ripemd160_digest_obj) },
};
STATIC MP_DEFINE_CONST_DICT(modngu_hash_ripemd160_locals_dict, modngu_hash_ripemd160_locals_dict_table);

STATIC const mp_obj_type_t modngu_hash_ripemd160_type = {
    { &mp_type_type },
    .name = MP_QSTR_ripemd160,
    .make_new = modngu_hash_ripemd160_make_new,
    .locals_dict = (void *)&modngu_hash_ripemd160_locals_dict,
};

// Double sha256 = sha256(sha256('foo').digest()).digest() ... in one step
STATIC mp_obj_t double_sha256(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    vstr_t vstr;
    vstr_init_len(&vstr, 32);

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (uint8_t *)inp.buf, inp.len);
    mbedtls_sha256_finish_ret(&ctx, (uint8_t *)vstr.buf);

    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, (uint8_t *)vstr.buf, 32);
    mbedtls_sha256_finish_ret(&ctx, (uint8_t *)vstr.buf);
    
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(double_sha256_obj, double_sha256);


STATIC const mp_rom_map_elem_t mp_module_hash_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hash) },

    { MP_ROM_QSTR(MP_QSTR_sha512), MP_ROM_PTR(&modngu_hash_sha512_type) },
    { MP_ROM_QSTR(MP_QSTR_ripemd160), MP_ROM_PTR(&modngu_hash_ripemd160_type) },
    { MP_ROM_QSTR(MP_QSTR_double_sha256), MP_ROM_PTR(&double_sha256_obj) },

};

STATIC MP_DEFINE_CONST_DICT(mp_module_hash_globals, mp_module_hash_globals_table);

const mp_obj_module_t mp_module_hash = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_hash_globals,
};

