# Desktop only: make test vectors
from base64 import b32encode, b32decode
import pycoin.encoding.b58
b58encode = pycoin.encoding.b58.b2a_hashed_base58
b58decode = pycoin.encoding.b58.a2b_hashed_base58

import sys
sys.path.append('../../libs/bech32/ref/python')
import segwit_addr

pat = b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd'

with open('test_codecs_gen.py', 'wt') as fd:
    print('''# AUTOGEN
try:
    from base64 import b32encode, b32decode

    import pycoin.encoding.b58
    b58encode = pycoin.encoding.b58.b2a_hashed_base58
    b58decode = pycoin.encoding.b58.a2b_hashed_base58
    ngu = None
except ImportError:
    import ngu
    b32encode = ngu.codecs.b32_encode
    b32decode = ngu.codecs.b32_decode

    b58encode = ngu.codecs.b58_encode
    b58decode = ngu.codecs.b58_decode
''', file=fd)

    for code in ['b32', 'b58']:
        for ln in range(1, 90, 7):
            vector = (pat*(1+(ln//32)))[0:ln]
            enc = eval(f'{code}encode(vector)')
            print(f'# len={ln}', file=fd)
            print(f'assert {vector!r} == {code}decode({enc!r}), "fail @ {ln}"', file=fd)
            print(f'assert {vector!r} == {code}decode({code}encode({vector!r})), "fail @ {ln}"', file=fd)


    print(f'\nif ngu:\n msg = {pat!r}', file=fd)
    for hrp in ['bc', 'tb']:
        for ver in [0, 1, 15]:
            for alen in [20, 32]:
                msg = pat[:alen]
                exp = segwit_addr.encode(hrp, ver, msg)
                print(f' assert ngu.codecs.segwit_decode({exp!r}) == ({hrp!r}, {ver}, msg[0:{alen}])', file=fd)
                print(f' assert ngu.codecs.segwit_encode({hrp!r}, {ver}, msg[0:{alen}]) == {exp!r}', file=fd)

    print("print('PASS - %s')" % fd.name, file=fd)

    print("run code now in: %s" % fd.name)

print('PASS - test_codecs')
