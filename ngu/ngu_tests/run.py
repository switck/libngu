# run and re-run all tests
import sys

# tests only execute on import, so reset
for n in list(sys.modules.keys()):
    if n.startswith('ngu_tests.'):
        del sys.modules[n]
sys.path.insert(0, '')

import ngu_tests.test_bip39
import ngu_tests.test_hash
import ngu_tests.test_hmac
import ngu_tests.test_random
import ngu_tests.test_cert
import ngu_tests.test_codecs_gen
import ngu_tests.test_hash_gen
import ngu_tests.test_hdnode
import ngu_tests.test_hdnode_gen
import ngu_tests.test_k1
import ngu_tests.test_k1_gen
import ngu_tests.test_ec
import ngu_tests.test_ec_gen
