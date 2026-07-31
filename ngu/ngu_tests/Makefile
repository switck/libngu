MPY = ../../ngu-micropython
PY = python3

.PHONY: test tests
test tests: cavp
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
	$(PY) test_hmac.py
	$(MPY) test_cert.py
	$(PY) test_ec.py
	$(MPY) test_ec.py
	$(MPY) test_ec_gen.py
	$(PY) test_bip39.py
	$(MPY) test_bip39.py
	$(MPY) test_bip32.py

# host-compiled checks of the DRBG against NIST CAVP vectors, one binary
# per SHA-256 backend so both compile paths stay honest
CIFRA = ../cifra
MBEDTLS = ../../libs/mpy/lib/mbedtls
CAVP_SRC = hmac_drbg_cavp.c ../hmac_drbg.c
CAVP_DEPS = $(CAVP_SRC) ../hmac_drbg.h hmac_drbg_cavp_vectors.h
CAVP_CC = $(CC) -Wall -Werror -O1 -I.. -DNGU_HMAC_DRBG_NO_MPCONFIG

cavp-cifra: $(CAVP_DEPS) $(CIFRA)/sha256.c $(CIFRA)/blockwise.c
	$(CAVP_CC) -I$(CIFRA) -I$(CIFRA)/ext -o $@ \
		$(CAVP_SRC) $(CIFRA)/sha256.c $(CIFRA)/blockwise.c

cavp-mbedtls: $(CAVP_DEPS) $(MBEDTLS)/library/sha256.c $(MBEDTLS)/library/platform_util.c
	$(CAVP_CC) -DMICROPY_SSL_MBEDTLS=1 -I$(MBEDTLS)/include -o $@ \
		$(CAVP_SRC) $(MBEDTLS)/library/sha256.c $(MBEDTLS)/library/platform_util.c

.PHONY: cavp
cavp: cavp-cifra cavp-mbedtls
	./cavp-cifra
	./cavp-mbedtls

# runs the test compiled in, not here
# or, on target
#	 import ngu_tests.run
run:
	$(MPY) run.py
