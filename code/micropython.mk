# this file autodetected by py/py.mk based on its name

SRC_USERMOD += $(addprefix $(NGU_TOP_DIR)/code/, hash.c modngu.c ec.c cert.c secp256k1.c)

CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/code -I$(NGU_TOP_DIR)/libs/secp256k1/include
LDFLAGS_USERMOD += $(NGU_TOP_DIR)/libs/secp256k1/.libs/libsecp256k1.a
 
FROZEN_MANIFEST += $(NGU_TOP_DIR)/code/manifest.py
