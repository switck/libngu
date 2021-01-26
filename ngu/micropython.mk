# this file autodetected by py/py.mk based on its name

MY_FILES = hash.c modngu.c ec.c cert.c k1.c random.c base32.c codecs.c \
			libbase58.c hdnode.c my_assert.c lib_secp256k1.c
SRC_USERMOD += $(addprefix $(NGU_TOP_DIR)/ngu/, $(MY_FILES))

CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/ngu -I$(NGU_TOP_DIR)/libs -DCONFIG_MBEDTLS_RIPEMD160_C=1
 
FROZEN_MANIFEST += $(NGU_TOP_DIR)/ngu/manifest.py

%/lib_secp256k1.o: \
	CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/libs/secp256k1/src -I$(NGU_TOP_DIR)/libs/secp256k1 \
						-Wno-unused-function
						
#-Wno-error=unused-function
