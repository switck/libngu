//
// hash.c - hash functions
//
// - sha256, single & double
// - sha512
// - ripemd160
// - has160, bitcoin specific
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

static mp_obj_t modngu_hash_sha512_update(mp_obj_t self_in, mp_obj_t arg) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);
    mp_buffer_info_t bufinfo;
    mp_get_buffer_raise(arg, &bufinfo, MP_BUFFER_READ);

#if MICROPY_SSL_MBEDTLS
    mbedtls_sha512_update((mbedtls_sha512_context *)self->state, bufinfo.buf, bufinfo.len);
#else
    cf_sha512_update((cf_sha512_context *)self->state, bufinfo.buf, bufinfo.len);
#endif

    return mp_const_none;
}

static mp_obj_t modngu_hash_sha512_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 1, false);

#if MICROPY_SSL_MBEDTLS
    // New v1.28 allocation: 4 arguments + correct field name + uintptr_t alignment
    size_t n = (sizeof(mbedtls_sha512_context) + sizeof(uintptr_t) - 1) / sizeof(uintptr_t);
    mp_obj_hash_t *o = m_new_obj_var(mp_obj_hash_t, state, uintptr_t, n);
    o->base.type = type;

    mbedtls_sha512_init((mbedtls_sha512_context *)o->state);
    mbedtls_sha512_starts((mbedtls_sha512_context *)o->state, false);
#else
    // Same pattern for the tinycrypt/cf fallback
    size_t n = (sizeof(cf_sha512_context) + sizeof(uintptr_t) - 1) / sizeof(uintptr_t);
    mp_obj_hash_t *o = m_new_obj_var(mp_obj_hash_t, state, uintptr_t, n);
    o->base.type = type;

    cf_sha512_init((cf_sha512_context *)o->state);
#endif

    if (n_args == 1) {
        modngu_hash_sha512_update(MP_OBJ_FROM_PTR(o), args[0]);
    }

    return MP_OBJ_FROM_PTR(o);
}

static mp_obj_t modngu_hash_sha512_digest(mp_obj_t self_in) {
    mp_obj_hash_t *self = MP_OBJ_TO_PTR(self_in);

    uint8_t rv[64];

#if MICROPY_SSL_MBEDTLS
    mbedtls_sha512_finish((mbedtls_sha512_context *)self->state, rv);
    mbedtls_sha512_free((mbedtls_sha512_context *)self->state);
#else
    cf_sha512_digest_final((cf_sha512_context *)self->state, rv);
#endif

    return mp_obj_new_bytes(rv, 64);
}

static MP_DEFINE_CONST_FUN_OBJ_2(modngu_hash_sha512_update_obj, modngu_hash_sha512_update);
static MP_DEFINE_CONST_FUN_OBJ_1(modngu_hash_sha512_digest_obj, modngu_hash_sha512_digest);

static const mp_rom_map_elem_t modngu_hash_sha512_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR_update), MP_ROM_PTR(&modngu_hash_sha512_update_obj) },
    { MP_ROM_QSTR(MP_QSTR_digest), MP_ROM_PTR(&modngu_hash_sha512_digest_obj) },
};
static MP_DEFINE_CONST_DICT(modngu_hash_sha512_locals_dict, modngu_hash_sha512_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    modngu_hash_sha512_type,
    MP_QSTR_sha512,
    MP_TYPE_FLAG_NONE,
    make_new, modngu_hash_sha512_make_new,
    locals_dict, &modngu_hash_sha512_locals_dict
);

// Tagged sha256 = SHA256(SHA256(tag)||SHA256(tag)||msg)
static mp_obj_t hm_tagged_sha256(size_t n_args, const mp_obj_t *args) {
    mp_obj_t tag = args[0];
    mp_obj_t msg = args[1];
    bool is_tag_hashed = false;
    if(n_args > 2) {
        is_tag_hashed = mp_obj_is_true(args[2]);
    }
    mp_buffer_info_t t;
    mp_buffer_info_t m;
    mp_get_buffer_raise(tag, &t, MP_BUFFER_READ);
    mp_get_buffer_raise(msg, &m, MP_BUFFER_READ);

    uint8_t s0[32];
    if (is_tag_hashed) {
        if (t.len != 32) {
            mp_raise_ValueError(MP_ERROR_TEXT("len tag_hash != 32"));
        }
        memcpy(s0, t.buf, 32);
    } else {
        sha256_single(t.buf, t.len, s0);
    }
    int ser_len = 64 + m.len;
    uint8_t ser[ser_len];
    memcpy(ser, s0, 32);
    memcpy(ser + 32, s0, 32);
    memcpy(ser + 64, m.buf, m.len);


    uint8_t res[32];
    sha256_single(ser, ser_len, res);

    return mp_obj_new_bytes(res, 32);
}
static MP_DEFINE_CONST_FUN_OBJ_VAR_BETWEEN(hm_tagged_sha256_obj,2,3, hm_tagged_sha256);

// Double sha256 = sha256(sha256('foo').digest()).digest() ... in one step
static mp_obj_t hm_double_sha256(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    uint8_t res[32];

    sha256_double(inp.buf, inp.len, res);
    
    return mp_obj_new_bytes(res, 32);
}
static MP_DEFINE_CONST_FUN_OBJ_1(hm_double_sha256_obj, hm_double_sha256);

// single-shot sha256/ripe/etc

static mp_obj_t hm_single_sha256(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    uint8_t res[32];

    sha256_single(inp.buf, inp.len, res);
    
    return mp_obj_new_bytes(res, 32);
}
static MP_DEFINE_CONST_FUN_OBJ_1(hm_single_sha256_obj, hm_single_sha256);

static mp_obj_t hm_single_ripemd160(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    uint8_t res[20];

#if 0
    mbedtls_ripemd160_context ctx;
    mbedtls_ripemd160_init(&ctx);
    mbedtls_ripemd160_starts(&ctx);
    mbedtls_ripemd160_update(&ctx, inp.buf, inp.len);
    mbedtls_ripemd160_finish(&ctx, res);
    mbedtls_ripemd160_free(&ctx);
#endif
    ripemd160(inp.buf, inp.len, res);
    
    return mp_obj_new_bytes(res, 20);
}
static MP_DEFINE_CONST_FUN_OBJ_1(hm_single_ripemd160_obj, hm_single_ripemd160);

static mp_obj_t hm_hash160(mp_obj_t arg) {
    mp_buffer_info_t inp;
    mp_get_buffer_raise(arg, &inp, MP_BUFFER_READ);

    uint8_t res[20];

    hash160(inp.buf, inp.len, res);
    
    return mp_obj_new_bytes(res, 20);
}
static MP_DEFINE_CONST_FUN_OBJ_1(hm_hash160_obj, hm_hash160);


// Pbkdf2 using sha512 hmac, for use in BIP39=>BIP32 seed
static mp_obj_t pbkdf2_sha512(mp_obj_t pass_in, mp_obj_t salt_in, mp_obj_t rounds_in) {
    mp_buffer_info_t pass, salt;
    mp_get_buffer_raise(pass_in, &pass, MP_BUFFER_READ);
    mp_get_buffer_raise(salt_in, &salt, MP_BUFFER_READ);
    const uint32_t H_SIZE = 64;      // because sha512

#if MICROPY_SSL_MBEDTLS
    const mbedtls_md_info_t *md_algo = mbedtls_md_info_from_type(MBEDTLS_MD_SHA512);
#endif

    uint32_t key_len = H_SIZE;
    uint8_t key_arr[H_SIZE];
    uint8_t *key = key_arr;

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

    return mp_obj_new_bytes(key_arr, H_SIZE);
}
static MP_DEFINE_CONST_FUN_OBJ_3(pbkdf2_sha512_obj, pbkdf2_sha512);


static const mp_rom_map_elem_t mp_module_hash_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_hash) },

    { MP_ROM_QSTR(MP_QSTR_sha512), MP_ROM_PTR(&modngu_hash_sha512_type) },
    { MP_ROM_QSTR(MP_QSTR_ripemd160), MP_ROM_PTR(&hm_single_ripemd160_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256s), MP_ROM_PTR(&hm_single_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256d), MP_ROM_PTR(&hm_double_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_sha256t), MP_ROM_PTR(&hm_tagged_sha256_obj) },
    { MP_ROM_QSTR(MP_QSTR_hash160), MP_ROM_PTR(&hm_hash160_obj) },
    { MP_ROM_QSTR(MP_QSTR_pbkdf2_sha512), MP_ROM_PTR(&pbkdf2_sha512_obj) },

};

static MP_DEFINE_CONST_DICT(mp_module_hash_globals, mp_module_hash_globals_table);
const mp_obj_module_t mp_module_hash = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_hash_globals,
};

void ripemd160(const uint8_t *msg, int msglen, uint8_t digest[20])
{
    if(msglen > 63) {
        mp_raise_ValueError(MP_ERROR_TEXT("limited to 63 bytes"));
    }

#if !defined(MP_ENDIANNESS_LITTLE)
#error "untested; suspect endian challenges here"
#endif

    if(((size_t)digest) & 0x3) {
        // unaligned case
        uint32_t    ctx[5];

        MDinit(ctx);
        MDfinish(ctx, msg, msglen, 0);

        memcpy(digest, ctx, 20);
    } else {
        // zero copy, works in place
        uint32_t    *ctx = (uint32_t *)digest;

        MDinit(ctx);
        MDfinish(ctx, msg, msglen, 0);
    }
}

void hash160(const uint8_t *msg, int msglen, uint8_t digest[20])
{
    // hash160(x) = ripemd160(sha256(x))
    uint8_t tmp[32];

    sha256_single(msg, msglen, tmp);
    ripemd160(tmp, 32, digest);
}

void sha256_single(const uint8_t *msg, int msglen, uint8_t digest[32])
{
#if MICROPY_SSL_MBEDTLS
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, msg, msglen);
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);
#elif defined(HASH_DATATYPE_8B)
    // Hardware Accelerated on this board.

    // setup
    MODIFY_REG(HASH->CR, HASH_CR_DATATYPE, HASH_DATATYPE_8B);
    __HAL_HASH_RESET_MDMAT();
    MODIFY_REG(HASH->CR, HASH_CR_LKEY|HASH_CR_ALGO|HASH_CR_MODE|HASH_CR_INIT,
                            HASH_ALGOSELECTION_SHA256 | HASH_CR_INIT);
    __HAL_HASH_SET_NBVALIDBITS(msglen);

    // write data
    // NOTE: this works great even when *msg is unaligned. Verified in test case
    uint32_t *ptr = (uint32_t *)msg;
    for(int i=0; i<msglen; i+=4, ptr++) {
        HASH->DIN = *ptr;
    }

    __HAL_HASH_START_DIGEST();

    // wait for DCIS flag to be set
    while(__HAL_HASH_GET_FLAG(HASH_FLAG_DCIS) == RESET) {
        // maybe: timeout?
    }

    // read result
    uint32_t *out = (uint32_t *)digest;

    *(out++) = __REV(HASH->HR[0]);
    *(out++) = __REV(HASH->HR[1]);
    *(out++) = __REV(HASH->HR[2]);
    *(out++) = __REV(HASH->HR[3]);
    *(out++) = __REV(HASH->HR[4]);
    *(out++) = __REV(HASH_DIGEST->HR[5]);
    *(out++) = __REV(HASH_DIGEST->HR[6]);
    *(out++) = __REV(HASH_DIGEST->HR[7]);
#else
    cf_hash(&cf_sha256, msg, msglen, digest);
#endif
}
    
void sha256_double(const uint8_t *msg, int msglen, uint8_t digest[32])
{
#if MICROPY_SSL_MBEDTLS
    // re-used ctx here (slight savings in stack depth)
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, msg, msglen);
    mbedtls_sha256_finish(&ctx, digest);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, digest, 32);
    mbedtls_sha256_finish(&ctx, digest);
    mbedtls_sha256_free(&ctx);
#else
    sha256_single(msg, msglen, digest);
    sha256_single(digest, 32, digest);
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
