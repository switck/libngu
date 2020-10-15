#NGU_TOP_DIR = 

SRC_USERMOD += $(addprefix $(NGU_TOP_DIR)/code/, hash.c modngu.c)

CFLAGS_USERMOD += -I$(NGU_TOP_DIR)/code


