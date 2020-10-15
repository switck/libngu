# this file autodetected by py/py.mk based on name

SRC_USERMOD += $(addprefix $(NGU_TOP_DIR)/code/, hash.c modngu.c)

CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/code

FROZEN_MANIFEST += $(NGU_TOP_DIR)/code/manifest.py
