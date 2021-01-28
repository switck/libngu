# Location of key submods
MPY_TOP ?= libs/micropython
S_TOP ?= libs/secp256k1

all: $(TARGET)

$(TARGET): $(REQUIRES)

# build a version of micropython (some port+board) that includes exactly what we need
$(TARGET): 
	cd $(MPY_PORT_DIR) && $(MAKE) $(MPY_MAKE_ARGS)

clean:
	cd $(MPY_PORT_DIR) && $(MAKE) $(MPY_MAKE_ARGS) clean

tags:
	ctags -f .tags ngu/*.[hc] \
	$(filter-out $(MPY_TOP)/py/dynruntime.h, $(wildcard $(MPY_TOP)/py/*.[hc])) \
	libs/secp256k1/{src,include}/*.[hc] \
	libs/secp256k1/src/modules/*/*.[hc] \
	libs/micropython/lib/mbedtls/include/mbedtls/*.h \
	libs/micropython/lib/mbedtls/crypto/library/*.c

test tests:
	(cd ngu/ngu_tests; make tests)

K1_CONF_FLAGS = --with-bignum=no --with-ecmult-window=8 --with-ecmult-gen-precision=2 \
				--enable-module-recovery --enable-module-extrakeys --enable-experimental \
				--enable-module-ecdh

.PHONY: one-time
one-time:
	cd $(S_TOP); ./autogen.sh && ./configure $(K1_CONF_FLAGS)
	

esp:
	make -f Makefile.esp32 && make -f Makefile.esp32 esp-deploy

quick: all
	make -f Makefile.unix
	./ngu-micropython -c 'import ngu_tests.run'

clobber:
	make -f makefile.unix clean
	make -f makefile.esp32 clean
	make -f makefile.stm32 clean
