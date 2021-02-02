//
// aes.c - Basic AES, not PEP-272
//
// - CBC and CTR only
//
#if NGU_INCL_AES
#include "py/runtime.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "my_assert.h"

#include "cifra/modes.h"
#include "cifra/aes.h"


typedef struct  {
    mp_obj_base_t base;
    bool        is_encrypt;
    cf_aes_context      aes_ctx;
    cf_cbc      mode_ctx;
} mp_obj_CBC_t;

typedef struct  {
    mp_obj_base_t base;
    cf_aes_context      aes_ctx;
    cf_ctr      mode_ctx;
} mp_obj_CTR_t;

STATIC const mp_obj_type_t s_CBC_type, s_CTR_type;

static void _aes_setup(cf_aes_context *aes_ctx, const mp_obj_t key_in)
{
    mp_buffer_info_t key;
    mp_get_buffer_raise(key_in, &key, MP_BUFFER_READ);

    switch(key.len) {
        case 16:
        case 24:
        case 32:
            break;
        default:
            mp_raise_ValueError(NULL);
    }

    cf_aes_init(aes_ctx, key.buf, key.len);
}

STATIC mp_obj_t s_CBC_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    // args: is_encrypt, key, iv?
    mp_arg_check_num(n_args, n_kw, 3, 3, false);

    mp_obj_CBC_t *o = m_new_obj_with_finaliser(mp_obj_CBC_t);
    o->base.type = type;

    o->is_encrypt = !!mp_obj_get_int_truncated(args[0]);

    _aes_setup(&o->aes_ctx, args[1]);

    mp_buffer_info_t iv;
    mp_get_buffer_raise(args[2], &iv, MP_BUFFER_READ);
    if(iv.len != CF_MAXBLOCK) {
        mp_raise_ValueError(MP_ERROR_TEXT("iv"));
    }

    cf_cbc_init(&o->mode_ctx, &cf_aes, &o->aes_ctx, iv.buf);
    
    return o;
}
STATIC mp_obj_t s_CTR_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    // args: key, nonce
    mp_arg_check_num(n_args, n_kw, 2, 2, false);

    mp_obj_CTR_t *o = m_new_obj_with_finaliser(mp_obj_CTR_t);
    o->base.type = type;

    _aes_setup(&o->aes_ctx, args[0]);

    mp_buffer_info_t nonce;
    mp_get_buffer_raise(args[1], &nonce, MP_BUFFER_READ);
    if(nonce.len != CF_MAXBLOCK) {
        mp_raise_ValueError(NULL);
    }

    cf_ctr_init(&o->mode_ctx, &cf_aes, &o->aes_ctx, nonce.buf);
    
    return o;
}

STATIC mp_obj_t s_CBC_cipher(mp_obj_t self_in, mp_obj_t buf_in)
{
    mp_buffer_info_t buf;
    mp_get_buffer_raise(buf_in, &buf, MP_BUFFER_READ);
    mp_obj_CBC_t *self = MP_OBJ_TO_PTR(self_in);

    assert(self->aes_ctx.rounds);

    vstr_t rv;
    vstr_init_len(&rv, buf.len);
    if(buf.len % CF_MAXBLOCK) {        // 16
        mp_raise_ValueError(NULL);
    }

    if(self->is_encrypt) {
        cf_cbc_encrypt(&self->mode_ctx, buf.buf, (uint8_t *)rv.buf, buf.len/CF_MAXBLOCK);
    } else {
        cf_cbc_decrypt(&self->mode_ctx, buf.buf, (uint8_t *)rv.buf, buf.len/CF_MAXBLOCK);
    }

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_CBC_cipher_obj, s_CBC_cipher);

STATIC mp_obj_t s_CTR_cipher(mp_obj_t self_in, mp_obj_t buf_in)
{
    mp_buffer_info_t buf;
    mp_get_buffer_raise(buf_in, &buf, MP_BUFFER_READ);
    mp_obj_CTR_t *self = MP_OBJ_TO_PTR(self_in);

    assert(self->aes_ctx.rounds);

    vstr_t rv;
    vstr_init_len(&rv, buf.len);

    // any size i/o works
    cf_ctr_cipher(&self->mode_ctx, buf.buf, (uint8_t *)rv.buf, buf.len);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &rv);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_2(s_CTR_cipher_obj, s_CTR_cipher);

STATIC mp_obj_t s_CBC_blank(mp_obj_t self_in) {
    mp_obj_CBC_t *self = MP_OBJ_TO_PTR(self_in);

    // cf_aes_finish is just this anyway
    memset(self, 0, sizeof(mp_obj_CBC_t));
    self->base.type = &s_CBC_type;
    
    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_CBC_blank_obj, s_CBC_blank);

STATIC mp_obj_t s_CTR_blank(mp_obj_t self_in) {
    mp_obj_CTR_t *self = MP_OBJ_TO_PTR(self_in);

    // cf_aes_finish is just this anyway
    memset(self, 0, sizeof(mp_obj_CTR_t));
    self->base.type = &s_CTR_type;
    
    return self_in;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(s_CTR_blank_obj, s_CTR_blank);


STATIC const mp_rom_map_elem_t s_CBC_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_cipher), MP_ROM_PTR(&s_CBC_cipher_obj) },
    { MP_ROM_QSTR(MP_QSTR_blank), MP_ROM_PTR(&s_CBC_blank_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&s_CBC_blank_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_CBC_locals_dict, s_CBC_locals_dict_table);

STATIC const mp_obj_type_t s_CBC_type = {
    { &mp_type_type },
    .name = MP_QSTR_CBC,
    .make_new = s_CBC_make_new,
    .locals_dict = (void *)&s_CBC_locals_dict,
};

STATIC const mp_rom_map_elem_t s_CTR_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_cipher), MP_ROM_PTR(&s_CTR_cipher_obj) },
    { MP_ROM_QSTR(MP_QSTR_blank), MP_ROM_PTR(&s_CTR_blank_obj) },
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&s_CTR_blank_obj) },
};
STATIC MP_DEFINE_CONST_DICT(s_CTR_locals_dict, s_CTR_locals_dict_table);

STATIC const mp_obj_type_t s_CTR_type = {
    { &mp_type_type },
    .name = MP_QSTR_CTR,
    .make_new = s_CTR_make_new,
    .locals_dict = (void *)&s_CTR_locals_dict,
};


STATIC const mp_rom_map_elem_t mp_module_aes_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_aes) },

    { MP_ROM_QSTR(MP_QSTR_CTR), MP_ROM_PTR(&s_CTR_type) },
    { MP_ROM_QSTR(MP_QSTR_CBC), MP_ROM_PTR(&s_CBC_type) },
};

STATIC MP_DEFINE_CONST_DICT(mp_module_aes_globals, mp_module_aes_globals_table);

const mp_obj_module_t mp_module_aes = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_aes_globals,
};

#endif
