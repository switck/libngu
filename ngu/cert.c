//
// cert.c - x.509 certificate parsing (limited)
//
// - want pubkey from cert
// - verify chain?
//
#include "py/runtime.h"
#if MICROPY_SSL_MBEDTLS
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "my_assert.h"

#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

// wrap lib calls with this to raise useful errors
#define CHECK_RESULT(funct)      { int rv = (funct); \
            if(rv) nlr_raise(mp_obj_new_exception_arg1(&mp_type_RuntimeError, \
                                                MP_OBJ_NEW_SMALL_INT(rv))); }

static const mp_obj_type_t cert_type;

typedef struct {
    mp_obj_base_t base;
    mbedtls_x509_crt   mcert;        // contains alloced data
} mp_obj_cert_t;


// Constructor
static mp_obj_t cert_make_new(const mp_obj_type_t *type, size_t n_args, size_t n_kw, const mp_obj_t *args) {
    mp_arg_check_num(n_args, n_kw, 0, 0, false);

    mp_obj_cert_t *o = (mp_obj_cert_t *)m_malloc_with_finaliser(sizeof(mp_obj_cert_t));
    o->base.type = type;

    mbedtls_x509_crt_init(&o->mcert);

    return MP_OBJ_FROM_PTR(o);
}

// Finalizer
static mp_obj_t cert_del(mp_obj_t self_in) {
    mp_obj_cert_t *self = MP_OBJ_TO_PTR(self_in);

    mbedtls_x509_crt_free(&self->mcert);

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_1(cert_del_obj, cert_del);


// Parse PEM (base64)
static mp_obj_t parse(mp_obj_t self_in, mp_obj_t data_in)
{
    mp_obj_cert_t *self = MP_OBJ_TO_PTR(self_in);

    const char *pem = mp_obj_str_get_str(data_in);

    // lib wants zero-terminated, and also a length.
    CHECK_RESULT(mbedtls_x509_crt_parse(&self->mcert, (uint8_t *)pem, strlen(pem)+1));

    return mp_const_none;
}
static MP_DEFINE_CONST_FUN_OBJ_2(parse_obj, parse);

// Verify chain
static mp_obj_t verify_chain(mp_obj_t self_in, mp_obj_t trust_ca_in)
{
    // TODO: add ca_crl, profile, etc.
    mp_obj_cert_t *self = MP_OBJ_TO_PTR(self_in);
    if(!mp_obj_is_type(trust_ca_in, &cert_type)) {
        mp_raise_TypeError(MP_ERROR_TEXT("need trust root"));
    }

    // TODO
#if 0
    mp_obj_cert_t *trust_ca = MP_OBJ_TO_PTR(trust_ca_in);

    

    int rv = x509_crt_verify_chain(&self->mcert, &trust_ca->mcert, NULL, &profile,
                &ver_chain, &restart_ctx);
#endif
    (void)self;
    int rv = -1;

    return MP_OBJ_NEW_SMALL_INT(rv);
}
static MP_DEFINE_CONST_FUN_OBJ_2(verify_chain_obj, verify_chain);

// get_ec_pubkey
static mp_obj_t get_ec_pubkey(mp_obj_t self_in)
{
    mp_obj_cert_t *self = MP_OBJ_TO_PTR(self_in);
    mbedtls_pk_context *pk = &self->mcert.pk;

    int ln = mbedtls_pk_get_len(pk);
    if(!ln) {
        mp_raise_ValueError(MP_ERROR_TEXT("empty cert"));
    }

    // ONLY supports 256 bit EC for now
    if(mbedtls_pk_get_type(pk) !=  MBEDTLS_PK_ECKEY) {
        mp_raise_TypeError(MP_ERROR_TEXT("only EC for now"));
    }

    unsigned char pk_buf[65];

    const mbedtls_ecp_keypair *pair = mbedtls_pk_ec(*pk);
    size_t actual = 0;

    CHECK_RESULT(mbedtls_ecp_point_write_binary(&pair->MBEDTLS_PRIVATE(grp), &pair->MBEDTLS_PRIVATE(Q),
                        MBEDTLS_ECP_PF_UNCOMPRESSED, &actual, pk_buf, 65));

    assert(actual == 65);

    return mp_obj_new_bytes(pk_buf, 65);
}
static MP_DEFINE_CONST_FUN_OBJ_1(get_ec_pubkey_obj, get_ec_pubkey);

// __repr__
static void cert_print(const mp_print_t *print, mp_obj_t self_in, mp_print_kind_t kind) {
    (void)kind;
    mp_obj_cert_t *self = MP_OBJ_TO_PTR(self_in);

    char nm[200] = "empty";
    mbedtls_x509_dn_gets(nm, sizeof(nm), &self->mcert.subject);

    mp_printf(print, "<x509 cert: %s>", nm);
}


static const mp_rom_map_elem_t cert_locals_dict_table[] = {
    { MP_ROM_QSTR(MP_QSTR___del__), MP_ROM_PTR(&cert_del_obj) },
    { MP_ROM_QSTR(MP_QSTR_parse), MP_ROM_PTR(&parse_obj) },
    { MP_ROM_QSTR(MP_QSTR_verify_chain), MP_ROM_PTR(&verify_chain_obj) },
    { MP_ROM_QSTR(MP_QSTR_get_ec_pubkey), MP_ROM_PTR(&get_ec_pubkey_obj) },
};
static MP_DEFINE_CONST_DICT(cert_locals_dict, cert_locals_dict_table);

static MP_DEFINE_CONST_OBJ_TYPE(
    cert_type,
    MP_QSTR_x509_cert,
    MP_TYPE_FLAG_NONE,
    print, cert_print,
    make_new, cert_make_new,
    locals_dict, &cert_locals_dict
);

static const mp_rom_map_elem_t globals_table[] = {
    { MP_ROM_QSTR(MP_QSTR___name__), MP_ROM_QSTR(MP_QSTR_cert) },
    { MP_ROM_QSTR(MP_QSTR_x509), MP_ROM_PTR(&cert_type) },
};

static MP_DEFINE_CONST_DICT(mod_globals, globals_table);

const mp_obj_module_t mp_module_cert = {
    .base = { &mp_type_module },
    .globals = (mp_obj_dict_t *)&mod_globals,
};

#endif
