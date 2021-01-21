//
// hash.c - less common or special hashers
//
// - sha512
// - ripemd160
//
#include "py/runtime.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "my_assert.h"

#if MICROPY_SSL_MBEDTLS
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha512.h"
#include "mbedtls/sha256.h"
#include "mbedtls/md.h"
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

// Pbkdf2 using sha512 hmac, for use in BIP39=>Bip32 seed
STATIC mp_obj_t pbkdf2_sha512(mp_obj_t pass_in, mp_obj_t salt_in, mp_obj_t rounds_in) {
    mp_buffer_info_t pass, salt;
    mp_get_buffer_raise(pass_in, &pass, MP_BUFFER_READ);
    mp_get_buffer_raise(salt_in, &salt, MP_BUFFER_READ);
    const uint32_t H_SIZE = 64;      // because sha512

    const mbedtls_md_info_t *md_algo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    vstr_t key_out;
    vstr_init_len(&key_out, H_SIZE);
    uint32_t key_len = H_SIZE;
    uint8_t *key = (uint8_t *)key_out.buf;

    // Based on https://github.com/openbsd/src/blob/master/lib/libutil/pkcs5_pbkdf2.c

    uint32_t rounds = mp_obj_get_int_truncated(rounds_in);
    if(rounds < 1) {
        mp_raise_ValueError(MP_ERROR_TEXT("rounds"));
    }
    if(!salt.len) {
        mp_raise_ValueError(MP_ERROR_TEXT("salt"));
    }

	uint8_t d1[H_SIZE], d2[H_SIZE], obuf[H_SIZE];

    uint8_t asalt[salt.len + 4];
	memcpy(asalt, salt.buf, salt.len);

	for(uint32_t count=1; key_len > 0; count++) {
		asalt[salt.len + 0] = (count >> 24) & 0xff;
		asalt[salt.len + 1] = (count >> 16) & 0xff;
		asalt[salt.len + 2] = (count >> 8) & 0xff;
		asalt[salt.len + 3] = count & 0xff;

        mbedtls_md_hmac(md_algo, pass.buf, pass.len, asalt, sizeof(asalt), d1);
		//hmac_sha256(asalt, salt_len + 4, pass.buf, pass.len, d1);
		memcpy(obuf, d1, H_SIZE);

		for(uint32_t i=1; i < rounds; i++) {
			//hmac_sha1(d1, sizeof(d1), pass.buf, pass.len, d2);
            mbedtls_md_hmac(md_algo, pass.buf, pass.len, d1, sizeof(d1), d2);
			memcpy(d1, d2, sizeof(d1));
			for (uint32_t j = 0; j < sizeof(obuf); j++)
				obuf[j] ^= d1[j];
		}

		uint32_t r = MIN(key_len, H_SIZE);
		memcpy(key, obuf, r);
		key += r;
		key_len -= r;
	};
/*
	explicit_bzero(asalt, sizeof(asalt));
	explicit_bzero(d1, sizeof(d1));
	explicit_bzero(d2, sizeof(d2));
	explicit_bzero(obuf, sizeof(obuf));
*/

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &key_out);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(pbkdf2_sha512_obj, pbkdf2_sha512);


STATIC const mp_rom_map_elem_t mp_module_hash_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hash) },

    { MP_ROM_QSTR(MP_QSTR_sha512), MP_ROM_PTR(&modngu_hash_sha512_type) },
    { MP_ROM_QSTR(MP_QSTR_ripemd160), MP_ROM_PTR(&modngu_hash_ripemd160_type) },
    { MP_ROM_QSTR(MP_QSTR_sha256d), MP_ROM_PTR(&double_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_pbkdf2_sha512), MP_ROM_PTR(&pbkdf2_sha512_obj) },

};

STATIC MP_DEFINE_CONST_DICT(mp_module_hash_globals, mp_module_hash_globals_table);

const mp_obj_module_t mp_module_hash = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_hash_globals,
};

