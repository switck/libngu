# Location of key submods
MPY_TOP ?= libs/micropython
S_TOP ?= libs/secp256k1

LIB_SECP256K1 = $(S_TOP)/.libs/libsecp256k1.a

# mac bugfix
export PKG_CONFIG_PATH=/usr/local/opt/libffi/lib/pkgconfig

SUB_MAKE_ARGS = -j 4 VARIANT=ngu VARIANT_DIR=$(realpath var) V=$(V) \
					USER_C_MODULES=$(realpath .) NGU_TOP_DIR=$(realpath .)

all: ngu-micropython

ngu-micropython: var/micropython $(LIB_SECP256K1)

# build a version of micropython (unix port) that includes exactly what we need
var/micropython: Makefile code/*.[ch] var/*
	cd $(MPY_TOP)/ports/unix && $(MAKE) $(SUB_MAKE_ARGS)

clean:
	cd $(MPY_TOP)/ports/unix && $(MAKE) $(SUB_MAKE_ARGS) clean


tags:
	ctags -f .tags code/*.[hc] $(filter-out $(MPY_TOP)/py/dynruntime.h, $(wildcard $(MPY_TOP)/py/*.[hc])) libs/secp256k1/{src,include}/*.[hc] libs/secp256k1/src/modules/*/*.[hc]

test:
	(cd code; make test)

S_CONF_FLAGS = --with-bignum=no --with-ecmult-window=8 --with-ecmult-gen-precision=2\
				--enable-module-recovery

$(LIB_SECP256K1): Makefile
	(cd $(S_TOP); ./autogen.sh && ./configure $(S_CONF_FLAGS) && make)

