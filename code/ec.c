//
// ec.c - elyptical curve stuff, but only a few "useful" curves
//
// - sign, verify sig
// - 256 bit curves only
//
#include "py/runtime.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#if MICROPY_SSL_MBEDTLS
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#else
# error "requires MBEDTLS"
#endif

typedef struct _mp_obj_curve_t {
    mp_obj_base_t base;

    mbedtls_ecp_group   grp;        // contains alloced data
} mp_obj_curve_t;

// wrap lib calls with this to raise useful errors
#define CHECK_RESULT(funct)      { int rv = (funct); \
            if(rv) nlr_raise(mp_obj_new_exception_arg1(&mp_type_RuntimeError, \
                                                MP_OBJ_NEW_SMALL_INT(__LINE__))); }


// Constructor
STATIC mp_obj_t curve_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 1, 1, false);

    mp_obj_curve_t *o = m_new_obj_with_finaliser(mp_obj_curve_t);
    o->base.type = type;
    mbedtls_ecp_group_init(&o->grp);

    mbedtls_ecp_group_id num = mp_obj_get_int(args[0]);
    CHECK_RESULT(mbedtls_ecp_group_load(&o->grp, num));

    return MP_OBJ_FROM_PTR(o);
}

// Finalizer
STATIC mp_obj_t curve_del(mp_obj_t self_in) {
    mp_obj_curve_t *self = MP_OBJ_TO_PTR(self_in);

    mbedtls_ecp_group_free(&self->grp);

    return mp_const_none;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_1(curve_del_obj, curve_del);


// Signing
STATIC mp_obj_t curve_sign(mp_obj_t self_in, mp_obj_t privkey_in, mp_obj_t digest_in)
{
    mp_obj_curve_t *self = MP_OBJ_TO_PTR(self_in);

    // read key
    mp_buffer_info_t pk_buf, digest;
    mp_get_buffer_raise(privkey_in, &pk_buf, MP_BUFFER_READ);
    if(pk_buf.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("pk len"));
    }
    mp_get_buffer_raise(digest_in, &digest, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("dig len"));
    }

    // bignums (allocing)
    mbedtls_mpi     privkey, r, s;
    mbedtls_mpi_init(&privkey);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    CHECK_RESULT(mbedtls_mpi_read_binary(&privkey, pk_buf.buf, 32));

    CHECK_RESULT(mbedtls_ecdsa_sign_det(&self->grp, &r, &s, &privkey, digest.buf, digest.len, MBEDTLS_MD_SHA256));

    mbedtls_mpi_free(&privkey);

    // convert (R,S) output pair to 64 bytes
    vstr_t vstr;
    vstr_init_len(&vstr, 64);

    uint8_t     *result = (uint8_t *)vstr.buf;
    CHECK_RESULT(mbedtls_mpi_write_binary(&r, &result[0], 32));
    CHECK_RESULT(mbedtls_mpi_write_binary(&s, &result[32], 32));

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);

    return mp_obj_new_str_from_vstr(&mp_type_bytes, &vstr);
}
STATIC MP_DEFINE_CONST_FUN_OBJ_3(curve_sign_obj, curve_sign);

// Verify
STATIC mp_obj_t curve_verify(size_t n_args, const mp_obj_t *args)
{
    mp_obj_curve_t *self = MP_OBJ_TO_PTR(args[0]);
    mp_obj_t pubkey_in = args[1];
    mp_obj_t sig_in = args[2];
    mp_obj_t digest_in = args[3];
    mp_obj_t rv = mp_const_none;

    // read values
    mp_buffer_info_t pubkey_buf, sig, digest;
    mp_get_buffer_raise(sig_in, &sig, MP_BUFFER_READ);
    if(sig.len != 64) {
        mp_raise_ValueError(MP_ERROR_TEXT("sig len != 64"));
    }
    mp_get_buffer_raise(digest_in, &digest, MP_BUFFER_READ);
    if(digest.len != 32) {
        mp_raise_ValueError(MP_ERROR_TEXT("dig len"));
    }
    mp_get_buffer_raise(pubkey_in, &pubkey_buf, MP_BUFFER_READ);
    if(pubkey_buf.len != 65) {
        mp_raise_ValueError(MP_ERROR_TEXT("pubkey len != 65"));
    }

    // bignums (allocing)
    mbedtls_mpi     r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    CHECK_RESULT(mbedtls_mpi_read_binary(&r, sig.buf, 32));
    CHECK_RESULT(mbedtls_mpi_read_binary(&s, ((uint8_t *)sig.buf)+32, 32));

    mbedtls_ecp_point   pubkey;
    mbedtls_ecp_point_init(&pubkey);
    CHECK_RESULT(mbedtls_ecp_point_read_binary(
                    &self->grp, &pubkey, pubkey_buf.buf, pubkey_buf.len));

    if( mbedtls_ecp_check_pubkey( &self->grp, &pubkey) != 0) {
        // pubkey not on curve!
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecp_point_free(&pubkey);

        mp_raise_ValueError(MP_ERROR_TEXT("pubkey vs. curve"));
    }

    int result = mbedtls_ecdsa_verify(&self->grp, digest.buf, digest.len, &pubkey, &r, &s);

    rv = (result == 0) ? mp_const_true : mp_const_false;

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_point_free(&pubkey);

    return rv;
}
STATIC MP_DEFINE_CONST_FUN_OBJ_VAR(curve_verify_obj, 4, curve_verify);


STATIC const mp_rom_map_elem_t curve_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&curve_del_obj) },
    { MP_ROM_QSTR(MP_QSTR_sign), MP_ROM_PTR(&curve_sign_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify), MP_ROM_PTR(&curve_verify_obj) },
};
STATIC MP_DEFINE_CONST_DICT(curve_locals_dict, curve_locals_dict_table);

STATIC const mp_obj_type_t modngu_ec_curve_type = {
    { &mp_type_type },
    .name = MP_QSTR_ec_curve,
    .make_new = curve_make_new,
    .locals_dict = (void *)&curve_locals_dict,
};

STATIC const mp_rom_map_elem_t mp_module_ec_globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_ec) },

    { MP_ROM_QSTR(MP_QSTR_curve), MP_ROM_PTR(&modngu_ec_curve_type) },

#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
    // useful for certs
    { MP_ROM_QSTR(MP_QSTR_NIST_P256), MP_ROM_INT(MBEDTLS_ECP_DP_SECP256R1) },
#endif 
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
    // dup w/ libsecp256k1 for cross-check
    { MP_ROM_QSTR(MP_QSTR_SECP256K1), MP_ROM_INT(MBEDTLS_ECP_DP_SECP256K1) },
#endif 
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
    // untested?
    { MP_ROM_QSTR(MP_QSTR_BP256R1), MP_ROM_INT(MBEDTLS_ECP_DP_BP256R1) },
#endif 

};

STATIC MP_DEFINE_CONST_DICT(mp_module_ec_globals, mp_module_ec_globals_table);

const mp_obj_module_t mp_module_ec = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mp_module_ec_globals,
};

