MPY = ../../ngu-micropython
PY = python3

.PHONY: test tests hash-drbg-cavp gates
test tests: hash-drbg-cavp gates
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
CIFRA_DRBG_CC = $(CC) -std=gnu99 -Wall -Wextra -Werror \
	-Wno-unused-but-set-variable -DFULL_FAT_ASSERT \
	-I$(CIFRA_SRC) -I$(CIFRA_SRC)/ext

hash-drbg-cavp: $(CIFRA_DRBG_SRCS)
	@set -e; bin=$$(mktemp /tmp/libngu-cifra-drbg.XXXXXX); \
		trap 'rm -f "$$bin"' 0; \
		$(CIFRA_DRBG_CC) -o "$$bin" $(CIFRA_DRBG_SRCS); \
		"$$bin" hashdrbg-sha256 hashdrbg-sha256-addnl

GATE_CC = $(CC) -fsyntax-only -std=gnu99 -Wall -Wextra -Werror -I..
GATE_SOURCE = gate-stubs/random_backend_gate.c
GATE_STM_BASE = $(GATE_CC) -DMICROPY_PY_STM=1 $(GATE_SOURCE)
GATE_STM = $(GATE_STM_BASE) -DMICROPY_HW_ENABLE_RNG=1
GATE_STM_MODULE_DISABLED = $(GATE_CC) -DMICROPY_PY_STM=0 $(GATE_SOURCE)
GATE_ESP = $(GATE_CC) -Igate-stubs -DESP_PLATFORM=1 $(GATE_SOURCE)

gates:
	@set -e; log=$$(mktemp /tmp/libngu-rng-gates.XXXXXX); \
		trap 'rm -f "$$log"' 0; \
		! $(GATE_STM_BASE) 2>"$$log"; \
		grep -q 'MICROPY_HW_ENABLE_RNG=1 or NGU_STM32_EXTERNAL_RNG_GET=1 required' "$$log"; \
		! $(GATE_STM_BASE) -DMICROPY_HW_ENABLE_RNG=0 2>"$$log"; \
		grep -q 'MICROPY_HW_ENABLE_RNG=1 or NGU_STM32_EXTERNAL_RNG_GET=1 required' "$$log"; \
		! $(GATE_STM_BASE) -DMICROPY_HW_ENABLE_RNG=2 2>"$$log"; \
		grep -q 'MICROPY_HW_ENABLE_RNG=1 or NGU_STM32_EXTERNAL_RNG_GET=1 required' "$$log"; \
		! $(GATE_STM_BASE) -DMICROPY_HW_ENABLE_RNG=0 -DNGU_STM32_EXTERNAL_RNG_GET=0 2>"$$log"; \
		grep -q 'MICROPY_HW_ENABLE_RNG=1 or NGU_STM32_EXTERNAL_RNG_GET=1 required' "$$log"; \
		! $(GATE_STM_BASE) -DMICROPY_HW_ENABLE_RNG=0 -DNGU_STM32_EXTERNAL_RNG_GET=2 2>"$$log"; \
		grep -q 'MICROPY_HW_ENABLE_RNG=1 or NGU_STM32_EXTERNAL_RNG_GET=1 required' "$$log"; \
		$(GATE_STM); \
		$(GATE_STM_BASE) -DMICROPY_HW_ENABLE_RNG=0 -DNGU_STM32_EXTERNAL_RNG_GET=1; \
		! $(GATE_STM_MODULE_DISABLED) 2>"$$log"; \
		grep -q 'MICROPY_HW_ENABLE_RNG=1 or NGU_STM32_EXTERNAL_RNG_GET=1 required' "$$log"; \
		$(GATE_STM_MODULE_DISABLED) -DMICROPY_HW_ENABLE_RNG=1; \
		$(GATE_STM_MODULE_DISABLED) -DNGU_STM32_EXTERNAL_RNG_GET=1; \
		! $(GATE_ESP) 2>"$$log"; \
		grep -q 'NGU_ESP32_RNG_IS_TRUE_RANDOM=1 required' "$$log"; \
		! $(GATE_ESP) -DNGU_ESP32_RNG_IS_TRUE_RANDOM=0 2>"$$log"; \
		grep -q 'NGU_ESP32_RNG_IS_TRUE_RANDOM=1 required' "$$log"; \
		! $(GATE_ESP) -DNGU_ESP32_RNG_IS_TRUE_RANDOM=2 2>"$$log"; \
		grep -q 'NGU_ESP32_RNG_IS_TRUE_RANDOM=1 required' "$$log"; \
		$(GATE_ESP) -DNGU_ESP32_RNG_IS_TRUE_RANDOM=1; \
		! $(GATE_STM) -DMICROPY_PY_THREAD=1 -DMICROPY_PY_THREAD_GIL=0 2>"$$log"; \
		grep -q 'ngu.random requires the GIL when threads are enabled' "$$log"; \
		$(GATE_STM) -DMICROPY_PY_THREAD=1 -DMICROPY_PY_THREAD_GIL=1; \
		$(GATE_STM) -DMICROPY_PY_THREAD=0 -DMICROPY_PY_THREAD_GIL=0; \
		echo "PASS - RNG backend gates"

# runs the test compiled in, not here
# or, on target
#	 import ngu_tests.run
run:
	$(MPY) run.py
