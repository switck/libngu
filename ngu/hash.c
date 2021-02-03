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
#include "hash.h"
#include "rmd160.h"

#if 0
// useful for testing Cifra on Unix port
#undef MICROPY_SSL_MBEDTLS
#endif

#if MICROPY_SSL_MBEDTLS
# include "mbedtls/ripemd160.h"
# include "mbedtls/sha512.h"
# include "mbedtls/sha256.h"
# include "mbedtls/md.h"
#else
# include "cifra/sha2.h"
# include "cifra/sha3.h"
# include "cifra/hmac.h"
# include "cifra/chash.h"
#endif

typedef struct _mp_obj_hash_t {
    mp_obj_base_t base;
    char state[0];
} mp_obj_hash_t;

void ripemd160(const uint8_t *msg, int msglen, uint8_t digest[20]);

//
// SHA512
//

STATIC mp_obj_t modngu_hash_sha512_update(mp_obj_t self_in, mp_obj_t arg);

STATIC mp_obj_t modngu_hash_sha512_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);
#if MICROPY_SSL_MBEDTLS
    mp_obj_hash_t *o = m_new_obj_var(mp_obj_hash_t, char, sizeof(mbedtls_sha512_context));
    o->base.type = type;

    mbedtls_sha512_init((mbedtls_sha512_context *)o->state);
    mbedtls_sha512_starts_ret((mbedtls_sha512_context *)o->state, false);
#else
    mp_obj_hash_t *o = m_new_obj_var(mp_obj_hash_t, char, sizeof(cf_sha512_context));
    o->base.type = type;
    cf_sha512_init((cf_sha512_context *)o->state);
#endif

    if(n_args == 1) {
        modngu_hash_sha512_update(MP_OBJ_FROM_PTR(o), args[0]);
    }

    return MP_OBJ_FROM_PTR(o);
}

STATIC mp_obj_t modngu_hash_sha512_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);

#if MICROPY_SSL_MBEDTLS
    mbedtls_sha512_update_ret((mbedtls_sha512_context *)self->state, bufinfo.buf, bufinfo.len);
#else
    cf_sha512_update((cf_sha512_context *)self->state, bufinfo.buf, bufinfo.len);
#endif

    return mp_const_none;
}

STATIC mp_obj_t modngu_hash_sha512_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);

    vstr_t vstr;
    vstr_init_len(&vstr, 64);

#if MICROPY_SSL_MBEDTLS
    mbedtls_sha512_finish_ret((mbedtls_sha512_context *)self->state, (byte *)vstr.buf);
    mbedtls_sha512_free((mbedtls_sha512_context *)self->state);
#else
    cf_sha512_digest_final((cf_sha512_context *)self->state, (byte *)vstr.buf);
#endif

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


// Double sha256 = sha256(sha256('foo').digest()).digest() ... in one step
STATIC mp_obj_t hm_double_sha256(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    vstr_t vstr;
    vstr_init_len(&vstr, 32);

    sha256_double(inp.buf, inp.len, (uint8_t *)vstr.buf);
    
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(hm_double_sha256_obj, hm_double_sha256);

// single-shot sha256/ripe/etc

STATIC mp_obj_t hm_single_sha256(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    vstr_t vstr;
    vstr_init_len(&vstr, 32);

#if MICROPY_SSL_MBEDTLS
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, inp.buf, inp.len);
    mbedtls_sha256_finish_ret(&ctx, (uint8_t *)vstr.buf);
    mbedtls_sha256_free(&ctx);
#else
    cf_hash(&cf_sha256, inp.buf, inp.len, (uint8_t *)vstr.buf);
#endif
    
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(hm_single_sha256_obj, hm_single_sha256);

STATIC mp_obj_t hm_single_ripemd160(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    vstr_t vstr;
    vstr_init_len(&vstr, 20);

#if 0
    mbedtls_ripemd160_context ctx;
    mbedtls_ripemd160_init(&ctx);
    mbedtls_ripemd160_starts_ret(&ctx);
    mbedtls_ripemd160_update_ret(&ctx, inp.buf, inp.len);
    mbedtls_ripemd160_finish_ret(&ctx, (uint8_t *)vstr.buf);
    mbedtls_ripemd160_free(&ctx);
#endif
    ripemd160(inp.buf, inp.len, (uint8_t *)vstr.buf);
    
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(hm_single_ripemd160_obj, hm_single_ripemd160);

STATIC mp_obj_t hm_hash160(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    vstr_t vstr;
    vstr_init_len(&vstr, 20);

    hash160(inp.buf, inp.len, (uint8_t *)vstr.buf);
    
    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(hm_hash160_obj, hm_hash160);


// Pbkdf2 using sha512 hmac, for use in BIP39=>BIP32 seed
STATIC mp_obj_t pbkdf2_sha512(mp_obj_t pass_in, mp_obj_t salt_in, mp_obj_t rounds_in) {
    mp_buffer_info_t pass, salt;
    mp_get_buffer_raise(pass_in, &pass, MP_BUFFER_READ);
    mp_get_buffer_raise(salt_in, &salt, MP_BUFFER_READ);
    const uint32_t H_SIZE = 64;      // because sha512

#if MICROPY_SSL_MBEDTLS
    const mbedtls_md_info_t *md_algo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
#endif

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

#if MICROPY_SSL_MBEDTLS
        mbedtls_md_hmac(md_algo, pass.buf, pass.len, asalt, sizeof(asalt), d1);
#else
        cf_hmac(pass.buf, pass.len, asalt, sizeof(asalt), d1, &cf_sha512);
#endif

		//hmac_sha256(asalt, salt_len + 4, pass.buf, pass.len, d1);
		memcpy(obuf, d1, H_SIZE);

		for(uint32_t i=1; i < rounds; i++) {
			//hmac_sha1(d1, sizeof(d1), pass.buf, pass.len, d2);
#if MICROPY_SSL_MBEDTLS
            mbedtls_md_hmac(md_algo, pass.buf, pass.len, d1, sizeof(d1), d2);
#else
            cf_hmac(pass.buf, pass.len, d1, sizeof(d1), d2, &cf_sha512);
#endif
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
    { MP_ROM_QSTR(MP_QSTR_ripemd160), MP_ROM_PTR(&hm_single_ripemd160_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256s), MP_ROM_PTR(&hm_single_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256d), MP_ROM_PTR(&hm_double_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_hash160), MP_ROM_PTR(&hm_hash160_obj) },
    { MP_ROM_QSTR(MP_QSTR_pbkdf2_sha512), MP_ROM_PTR(&pbkdf2_sha512_obj) },

};

STATIC MP_DEFINE_CONST_DICT(mp_module_hash_globals, mp_module_hash_globals_table); 
const mp_obj_module_t mp_module_hash = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_hash_globals,
};

void ripemd160(const uint8_t *msg, int msglen, uint8_t digest[20])
{
    if(msglen > 63) {
        mp_raise_ValueError(MP_ERROR_TEXT("limited to 63 bytes"));
    }

#if defined(MP_ENDIANNESS_LITTLE)
    // look ma: zero copy
    uint32_t    *ctx = (uint32_t *)digest;

    MDinit(ctx);
    MDfinish(ctx, msg, msglen, 0);
#else
    uint32_t    ctx[5];

    MDinit(ctx);
    MDfinish(ctx, msg, msglen, 0);
    memcpy(digest, ctx, 20);        // endian?
#error "untested"
#endif
}

void hash160(const uint8_t *msg, int msglen, uint8_t digest[20])
{
    // hash160(x) = ripemd160(sha256(x))
    uint8_t tmp[32];

#if MICROPY_SSL_MBEDTLS
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, msg, msglen);
    mbedtls_sha256_finish_ret(&ctx, tmp);
    mbedtls_sha256_free(&ctx);
    
#if 0
    mbedtls_ripemd160_context    r_ctx;
    mbedtls_ripemd160_init(&r_ctx);
    mbedtls_ripemd160_starts_ret(&r_ctx);
    mbedtls_ripemd160_update_ret(&r_ctx, tmp, 32);
    mbedtls_ripemd160_finish_ret(&r_ctx, digest);
    mbedtls_ripemd160_free(&r_ctx);
#endif
    ripemd160(tmp, 32, digest);

#else
    cf_hash(&cf_sha256, msg, msglen, tmp);
    ripemd160(tmp, 32, digest);
#endif
}

void sha256_single(const uint8_t *msg, int msglen, uint8_t digest[32])
{
#if MICROPY_SSL_MBEDTLS
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, msg, msglen);
    mbedtls_sha256_finish_ret(&ctx, digest);
    mbedtls_sha256_free(&ctx);
#else
    cf_hash(&cf_sha256, msg, msglen, digest);
#endif
}

void hmac_sha512(const uint8_t *key, uint32_t key_len,
                    const uint8_t *data, uint32_t data_len,
                    left_right_t *result)
{
#if MICROPY_SSL_MBEDTLS
    STATIC_ASSERT(sizeof(left_right_t) == 64);
    const mbedtls_md_info_t *md_algo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);

    mbedtls_md_hmac(md_algo, key, key_len, data, data_len, result->both);
#else
    cf_hmac(key, key_len, data, data_len, result->both, &cf_sha512);
#endif
}

    
void sha256_double(const uint8_t *msg, int msglen, uint8_t digest[32])
{
#if MICROPY_SSL_MBEDTLS
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, msg, msglen);
    mbedtls_sha256_finish_ret(&ctx, digest);

    mbedtls_sha256_starts_ret(&ctx, 0);
    mbedtls_sha256_update_ret(&ctx, digest, 32);
    mbedtls_sha256_finish_ret(&ctx, digest);
    mbedtls_sha256_free(&ctx);
#else
    cf_hash(&cf_sha256, msg, msglen, digest);
    cf_hash(&cf_sha256, digest, 32, digest);
#endif
}
