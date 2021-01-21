
import ngu
#from ngu.hdnode import HDNode
HDNode = ngu.hdnode.HDNode

a = HDNode()
a.deserialize('xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6')
s = a.serialize(0x0488B21E, 0)
assert s[0:4] == 'xpub'
assert len(ngu.codecs.b58decode(s)) == 78

b = HDNode()
vo = b.deserialize(s)
assert vo == 0x0488B21E, hex(vo)

if 1:
    import json, bip39
    from binascii import a2b_hex, b2a_hex

    eng = json.load(open('b39-vectors.json'))['english']
    for raw, words, ms, xprv in eng:
        ms = a2b_hex(ms)
        x = HDNode()
        x.from_master(ms)
        assert x.serialize(0x0488ADE4, 1) == xprv

print('PASS')
