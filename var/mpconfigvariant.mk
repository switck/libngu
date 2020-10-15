# see libs/micropython/ports/unix/Makefile

COPT += 

#SRC_MOD += hash.c modngu.c
#USER_C_MODULES += $(realpath ..)

PROG = ngu-micropython

MICROPY_SSL_AXTLS = 0
MICROPY_SSL_MBEDTLS = 1


