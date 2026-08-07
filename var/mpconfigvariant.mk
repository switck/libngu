# see libs/mpy/ports/unix/Makefile

COPT += 

#SRC_MOD += hash.c modngu.c
#USER_C_MODULES += $(realpath ..)

PROG = ngu-micropython

MICROPY_SSL_AXTLS = 0
MICROPY_SSL_MBEDTLS = 1

# ngu.random holds mutable DRBG and source-check state.
MICROPY_PY_THREAD = 0
