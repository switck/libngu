# Location of key submods
MPY_TOP ?= libs/mpy
S_TOP ?= libs/secp256k1
MBED_TOP ?= $(MPY_TOP)/lib/mbedtls

BECH32_PATCH ?= cd libs/bech32; git apply ../../bech32.patch || true
MPY_PATCH    ?=	cd libs/mpy; git apply ../../mpy.patch || true

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
	libs/cifra/src/*.[hc] ngu/bech32/*.[hc] \
	$(MBED_TOP)/include/mbedtls/*.h $(MBED_TOP)/library/*.c

test tests:
	(cd ngu/ngu_tests; make tests)

# DEVELOPER NOTE
# adjusting values in secp256k1 configure must match ngu/lib_secp256k1.c (after v0.3.0)
K1_CONF_FLAGS = --with-ecmult-window=2 --with-ecmult-gen-kb=2 --enable-module-recovery

.PHONY: one-time
one-time:
	cd $(MPY_TOP); git submodule update
	$(BECH32_PATCH)
	$(MPY_PATCH)
	cd $(MPY_TOP)/mpy-cross; make
	cd $(S_TOP); ./autogen.sh && ./configure $(K1_CONF_FLAGS) && make precomp
	
# get ready to build library, but not full Micropython nor Unix test code
.PHONY: min-one-time
min-one-time:
	cd libs; git submodule update --init bech32 cifra secp256k1
	$(BECH32_PATCH)
	$(MPY_PATCH)
	cd $(S_TOP); ./autogen.sh && ./configure $(K1_CONF_FLAGS) && make precomp

esp:
	make -f Makefile.esp32 && make -f Makefile.esp32 deploy
	echo "Run: import ngu_tests.run"

quick:
	make -f makefile.unix
	(cd ngu/ngu_tests; make)

relink:
	$(RM) $(TARGET)

clobber:
	make -f makefile.unix clean
	make -f makefile.esp32 clean
	make -f makefile.stm32 clean

