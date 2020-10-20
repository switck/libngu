# see also micropython.mk

MPY = ../ngu-micropython
PY = python3

all:
	(cd ..; make)
tags:
	(cd ..; make tags)

test:
	$(MPY) test_random.py
	$(MPY) test_k1.py
	$(PY) test_hmac.py
	$(MPY) test_hmac.py
	$(MPY) test_cert.py
	$(PY) test_ec.py
	$(MPY) test_ec.py
	$(MPY) test_ec_sig.py
	$(PY) test_bip39.py
	$(MPY) test_bip39.py
	$(PY) test_hash.py
	$(MPY) test_hash.py
