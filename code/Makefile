# see also micropython.mk

MPY = ../ngu-micropython
PY = python3

all:
	(cd ..; make)
tags:
	(cd ..; make tags)

test tests:
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
	$(MPY) test_hmac.py
	$(MPY) test_cert.py
	$(PY) test_ec.py
	$(MPY) test_ec.py
	$(MPY) test_ec_sig.py
	$(PY) test_bip39.py
	$(MPY) test_bip39.py
