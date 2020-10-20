# secp256k1

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

sig3 = ngu.secp256k1.signature(sig2.to_bytes()[:-1] + b'\0')
pubkey3 = sig3.verify_recover(md)
assert pubkey3 != pubkey

print("PASS")
