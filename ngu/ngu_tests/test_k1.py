try:
    # Desktop: make test vectors
    from ecdsa import SigningKey
    from ecdsa.util import sigencode_string
    from ecdsa.curves import SECP256k1
    from ecdsa.util import number_to_string
    from hashlib import sha256

    my_k = SigningKey.from_string(b'za'*16, curve=SECP256k1, hashfunc=sha256)

    with open('test_k1_gen.py', 'wt') as fd:
        print("import gc, ngu  # auto-gen", file=fd)
        print("my_pubkey = b'\\x04' + %r" % my_k.get_verifying_key().to_string(), file=fd)

        for pk in [b'12'*16, b'\x0f'+(b'\xff'*31), bytes(31)+b'\x01']:
            key = SigningKey.from_string(pk, curve=SECP256k1, hashfunc=sha256)
            expect = key.get_verifying_key().to_string('compressed')
            print('x = ngu.secp256k1.keypair(%r)' % pk, file=fd)
            print('assert x.pubkey().to_bytes() == %r\n\n' % expect, file=fd)

            # ECDH
            pt = my_k.privkey.secret_multiplier * key.get_verifying_key().pubkey.point
            kk = number_to_string(pt.x(), SECP256k1.order) \
                                    + number_to_string(pt.y(), SECP256k1.order)
            md = sha256(kk).digest()
            print('assert x.ecdh_multiply(my_pubkey) == %r\n\n' % md, file=fd)

        print("print('PASS - %s')" % fd.name, file=fd)
        print("run code now in: %s" % fd.name)

    import sys
    sys.exit(0)
except ImportError: 
    pass

import ngu

# pubkeys
p = ngu.secp256k1.pubkey(b'\x02'*33)
assert p.to_bytes() == p.to_bytes(False) == b'\x02'*33

odd = b'\x03'+'\x02'*32
p = ngu.secp256k1.pubkey(odd)
assert p.to_bytes() == odd

uncomp = p.to_bytes(True)
p2 = ngu.secp256k1.pubkey(uncomp)
assert p2.to_bytes(True) == uncomp
assert p.to_bytes() == odd != uncomp

# sigs
pk = b'x'*32
md = b'z'*32
sig = ngu.secp256k1.sign(pk, md)
assert len(sig.to_bytes()) == 65
pubkey = sig.verify_recover(md)
assert len(pubkey.to_bytes()) == 33

sig2 = ngu.secp256k1.sign(pk, md)
assert sig.to_bytes() == sig2.to_bytes()

pair = ngu.secp256k1.keypair(pk)
assert pair.privkey() == pk
sig4 = ngu.secp256k1.sign(pair, md)
assert sig.to_bytes() == sig4.to_bytes()

sig3 = ngu.secp256k1.signature(sig2.to_bytes()[:-1] + b'\0')
pubkey3 = sig3.verify_recover(md)
assert pubkey3 != pubkey

# privkeys look random
got = set()
for i in range(50):
    p1 = ngu.secp256k1.keypair()
    bs = p1.privkey()
    assert len(set(bs)) > 8
    assert bs not in got
    got.add(bs)
    assert p1.pubkey()

print("PASS - test_k1")
