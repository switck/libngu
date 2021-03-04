# this file autodetected by py/py.mk based on its name

NGU_TOP_DIR := $(realpath $(USERMOD_DIR)/..)

MY_FILES = hash.c modngu.c ec.c cert.c k1.c random.c base32.c codecs.c hm.c \
			libbase58.c hdnode.c my_assert.c lib_secp256k1.c \
			rmd160.c aes.c lib_segwit.c

CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/ngu -I$(NGU_TOP_DIR)/libs
 
FROZEN_MANIFEST += $(NGU_TOP_DIR)/ngu/manifest.py

%/lib_secp256k1.o: \
	CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/libs/secp256k1/src -I$(NGU_TOP_DIR)/libs/secp256k1 \
						-Wno-unused-function -Wno-nonnull-compare

%/lib_segwit.o: CFLAGS += -Wno-return-type

ifdef NGU_NEEDS_CIFRA

CFLAGS_USERMOD += -DNGU_INCL_AES=1

CIFRA_SRC = $(NGU_TOP_DIR)/libs/cifra/src
CIFRA_CFLAGS = $(CFLAGS) -DFULL_FAT_ASSERT -I$(NGU_TOP_DIR)/libs/cifra/src \
					-I$(NGU_TOP_DIR)/libs/cifra/src/ext
CIFRA_PARTS = hmac.o sha1.o sha3.o sha256.o sha512.o pbkdf2.o chash.o blockwise.o \
				aes.o modes.o
CIFRA_OBJS = $(addprefix $(CIFRA_SRC)/, $(CIFRA_PARTS))

# Because this isn't a single C file, we can't add it to SRC_USERMOD, since
# the py.mk makefile makes many assumptions from there. Instead, we
# add it as a object file, and provide a special rule to build it.
# Remaining problem: PY_O cannot be extended here, without changing py.mk a little.

$(BUILD)/hack_lib_cifra.o:
	@echo HACKING target: $@
	$(RM) -f $(CIFRA_OBJS)
	(cd $(NGU_TOP_DIR)/libs/cifra/src; $(MAKE) CC=$(CC) CFLAGS="$(CIFRA_CFLAGS)" $(CIFRA_PARTS))
	$(CC) -r -o $@ $(CIFRA_CFLAGS) $(CIFRA_OBJS)

PY_O += $(BUILD)/hack_lib_cifra.o

endif

SRC_USERMOD += $(addprefix $(USERMOD_DIR)/, $(MY_FILES))

