# see libs/mpy/ports/unix/Makefile

COPT += 

#SRC_MOD += hash.c modngu.c
#USER_C_MODULES += $(realpath ..)

PROG = ngu-micropython

MICROPY_SSL_AXTLS = 0
MICROPY_SSL_MBEDTLS = 1



# ngu.random's DRBG state assumes single-threaded callers (as firmware
# targets are); build the test interpreter without threads so the
# supported unix configuration matches that contract.
MICROPY_PY_THREAD = 0
