# secp256k1

import ngu

p = ngu.secp256k1.pubkey(b'\x02'*33)
assert p.to_bytes() == p.to_bytes(False) == b'\x02'*33

odd = b'\x03'+'\x02'*32
p = ngu.secp256k1.pubkey(odd)
assert p.to_bytes() == odd

uncomp = p.to_bytes(True)
p2 = ngu.secp256k1.pubkey(uncomp)
assert p2.to_bytes(True) == uncomp
assert p.to_bytes() == odd

print("PASS")
