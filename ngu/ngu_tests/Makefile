MPY = ../../ngu-micropython
PY = python3

.PHONY: test tests hash-drbg-cavp entropy-health
test tests: hash-drbg-cavp entropy-health
	test x$(VIRTUAL_ENV) != x		# need virtualenv
	$(PY) test_aes.py
	$(MPY) test_aes_gen.py
	$(PY) test_hdnode.py
	$(MPY) test_hdnode.py
	$(MPY) test_hdnode_gen.py
	$(PY) test_hash.py
	$(MPY) test_hash.py
	$(MPY) test_hash_gen.py
	$(PY) test_codecs.py
	$(PY) test_codecs_gen.py
	$(MPY) test_codecs_gen.py
	$(MPY) test_random.py
	$(PY) test_k1.py
	$(MPY) test_k1.py
	$(MPY) test_k1_gen.py
	$(MPY) test_schnorr.py
	$(MPY) test_musig.py
	$(PY) test_hmac.py
	$(MPY) test_cert.py
	$(PY) test_ec.py
	$(MPY) test_ec.py
	$(MPY) test_ec_gen.py
	$(PY) test_bip39.py
	$(MPY) test_bip39.py
	$(MPY) test_bip32.py

CIFRA_SRC = ../../libs/cifra/src
CIFRA_DRBG_SRCS = $(CIFRA_SRC)/testdrbg.c $(CIFRA_SRC)/drbg.c \
	$(CIFRA_SRC)/sha1.c $(CIFRA_SRC)/sha256.c $(CIFRA_SRC)/sha512.c \
	$(CIFRA_SRC)/blockwise.c $(CIFRA_SRC)/hmac.c $(CIFRA_SRC)/chash.c
CIFRA_DRBG_CC = $(CC) -std=gnu99 -Wall -Wextra -Werror -DFULL_FAT_ASSERT \
	-I$(CIFRA_SRC) -I$(CIFRA_SRC)/ext

hash-drbg-cavp: $(CIFRA_DRBG_SRCS)
	@set -e; bin=$$(mktemp /tmp/libngu-cifra-drbg.XXXXXX); \
		trap 'rm -f "$$bin"' 0; \
		$(CIFRA_DRBG_CC) -o "$$bin" $(CIFRA_DRBG_SRCS); \
		"$$bin" hashdrbg-sha256 hashdrbg-sha256-addnl

entropy-health: entropy_health_test.c ../entropy_health.h
	@set -e; bin=$$(mktemp /tmp/libngu-entropy-health.XXXXXX); \
		trap 'rm -f "$$bin"' 0; \
		$(CC) -std=c99 -Wall -Wextra -Werror -I.. -o "$$bin" entropy_health_test.c; \
		"$$bin"

# runs the test compiled in, not here
# or, on target
#	 import ngu_tests.run
run:
	$(MPY) run.py
