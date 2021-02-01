# this file autodetected by py/py.mk based on its name

MY_FILES = hash.c modngu.c ec.c cert.c k1.c random.c base32.c codecs.c hm.c \
			libbase58.c hdnode.c my_assert.c lib_secp256k1.c \
			rmd160.c

CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/ngu -I$(NGU_TOP_DIR)/libs
# -DCONFIG_MBEDTLS_RIPEMD160_C=1
 
FROZEN_MANIFEST += $(NGU_TOP_DIR)/ngu/manifest.py

%/lib_secp256k1.o: \
	CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/libs/secp256k1/src -I$(NGU_TOP_DIR)/libs/secp256k1 \
						-Wno-unused-function

ifdef NGU_NEEDS_CIFRA
MY_FILES += lib_cifra.c

%/lib_cifra.o: \
	CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/libs/cifra/src -I$(NGU_TOP_DIR)/libs/cifra/src/ext

CIFRA_SRC = $(NGU_TOP_DIR)/libs/cifra/src
CIFRA_PARTS = hmac.o sha1.o sha3.o sha256.o sha512.o pbkdf2.o chash.o blockwise.o
CIFRA_OBJS = $(addprefix $(CIFRA_SRC)/, $(CIFRA_PARTS))

#%/lib_cifra.o: $(CIFRA_OBJS)
%/lib_cifra.o:
	echo target: $@
	$(RM) -f $(CIFRA_OBJS)
	(cd $(NGU_TOP_DIR)/libs/cifra/src; $(MAKE) CC=$(CC) CFLAGS="$(CFLAGS) -DFULL_FAT_ASSERT" $(CIFRA_PARTS))
	$(AR) r $@ $(CIFRA_OBJS)
	$(AR) s $@

endif

SRC_USERMOD += $(addprefix $(NGU_TOP_DIR)/ngu/, $(MY_FILES))
