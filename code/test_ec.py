try:
    # Desktop: make test vectors
    from ecdsa import SigningKey, VerifyingKey
    from ecdsa.util import sigencode_string
    from ecdsa.curves import SECP256k1, BRAINPOOLP256r1, NIST256p
    from hashlib import sha256

    with open('test_ec_sig.py', 'wt') as fd:
        print("import ngu   # auto-gen/no-edit", file=fd)

        pks = [ b'\x55'*32, b'\x0f'+(b'\xff'*31)]
        md = b'MSG1'*8
        for pk in pks:
            for name, c in [ ('SECP256K1', SECP256k1), 
                                ('BP256R1', BRAINPOOLP256r1), 
                                ('NIST_P256', NIST256p) ]:

                key = SigningKey.from_string(pk, curve=c, hashfunc=sha256)
                rv = key.sign_digest_deterministic(md, hashfunc=sha256, sigencode=sigencode_string)

                print('assert ngu.ec.curve(ngu.ec.%s).sign(%r, %r) == %r' % (
                        name, pk, md, rv), file=fd)

        print("print('PASS')", file=fd)
        print("run code now in: %s" % fd.name)

    import sys
    sys.exit(0)
except ImportError: 
    pass

# Embedded tests

import gc
import ngu

names = [i for i in dir(ngu.ec) if i[0].isupper() and i[0].isalpha]
print("Curves: " + ', '.join(names))

# instance each one
for n in names:
    grp = ngu.ec.curve(getattr(ngu.ec, n))
    del grp
    gc.collect()

try:
    ngu.ec.curve(3847)
    assert False
except RuntimeError:
    pass

print('PASS')
