# Location of top-level MicroPython directory
MPY_TOP ?= libs/micropython
MP_CONFIGFILE ?= $(MPY_TOP)/ports/unix/mpconfigport.h

export PKG_CONFIG_PATH=/usr/local/opt/libffi/lib/pkgconfig

#CFLAGS += -I$(MPY_TOP) -I$(MPY_TOP)/ports/unix/build -DMP_CONFIGFILE="\""$(realpath $(MP_CONFIGFILE))"\""

#C_FILES = modngu.c hash.c
#OBJ_FILES = $(C_FILES:%.c=%.o)

SUB_MAKE_ARGS = -j 4 VARIANT=ngu VARIANT_DIR=$(realpath var) V=$(V) \
					USER_C_MODULES=$(realpath .) NGU_TOP_DIR=$(realpath .)

# All source files (.c or .py)
SRC = moduqr.c hash.c

all: ngu-micropython

ngu-micropython: var/micropython

# build a version of micropython (unix port) that includes exactly what we need
var/micropython: Makefile code/*.[ch] var/*
	cd $(MPY_TOP)/ports/unix && $(MAKE) $(SUB_MAKE_ARGS)

clean:
	cd $(MPY_TOP)/ports/unix && $(MAKE) $(SUB_MAKE_ARGS) clean


tags:
	ctags -f .tags *.[ch]

test:
	(cd code; make test)
