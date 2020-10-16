MPY = ../ngu-micropython
PY = python3

all:
	(cd ..; make)

test:
	$(PY) test_ec.py
	$(MPY) test_ec.py
	$(MPY) test_ec_sig.py
	$(PY) test_bip39.py
	$(MPY) test_bip39.py
	$(PY) test_hash.py
	$(MPY) test_hash.py
