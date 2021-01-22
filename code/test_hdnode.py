try:
    # Desktop: make test vectors
    from hashlib import sha256
    import wallycore as w

    with open('test_hdnode_gen.py', 'wt') as fd:
        print("import gc, ngu  # auto-gen", file=fd)
        print("HDNode = ngu.hdnode.HDNode", file=fd)

        print("for i in range(3):", file=fd)
        ms = b'1'*32
        for i in range(10):
            ms = sha256(ms).digest()
            node = w.bip32_key_from_seed(ms, 0x488ade4, 0)
            pub = w.bip32_key_get_pub_key(node)
            priv = w.bip32_key_get_priv_key(node)
            fp = bytearray(4)
            w.bip32_key_get_fingerprint(node, fp)
            xprv = w.base58check_from_bytes(w.bip32_key_serialize(node, 0))
            xpub = w.base58check_from_bytes(w.bip32_key_serialize(node, w.BIP32_FLAG_KEY_PUBLIC))
            print("  a = HDNode(); a.from_master(%r)" % ms, file=fd)
            print("  assert a.pubkey() == %r" % pub, file=fd)
            print("  assert a.privkey() == %r" % priv, file=fd)
            print("  assert a.my_fp() == 0x%s" % fp.hex(), file=fd)
            print("  assert a.serialize(0x488ade4, 1) == %r" % xprv, file=fd)
            print("  assert a.serialize(0x488b21e, 0) == %r" % xpub, file=fd)
            print("  ", file=fd)

        print("print('PASS')", file=fd)
        print("run code now in: %s" % fd.name)

    import sys
    sys.exit(0)
except ImportError: 
    pass


import ngu
#from ngu.hdnode import HDNode
HDNode = ngu.hdnode.HDNode

def test_serial():
    a = HDNode()
    a.deserialize('xprv9s21ZrQH143K3FperxDp8vFsFycKCRcJGAFmcV7umQmcnMZaLtZRt13QJDsoS5F6oYT6BB4sS6zmTmyQAEkJKxJ7yByDNtRe5asP2jFGhT6')
    s = a.serialize(0x0488B21E, 0)
    assert s[0:4] == 'xpub'
    assert len(ngu.codecs.b58decode(s)) == 78

    b = HDNode()
    vo = b.deserialize(s)
    assert vo == 0x0488B21E, hex(vo)

def test_b39():
    import json, bip39
    from binascii import a2b_hex, b2a_hex

    eng = json.load(open('b39-vectors.json'))['english']
    for raw, words, ms, xprv in eng:
        ms = a2b_hex(ms)
        x = HDNode()
        x.from_master(ms)
        assert x.serialize(0x0488ADE4, 1) == xprv

def test_derive():
    a = HDNode()
    a.from_master(b'1'*32)
    assert a.depth() == 0
    assert a.parent_fp() == 0
    m_fp = a.my_fp()
    assert m_fp == 0x600f4faf           # matches wallycore
    p1 = a.derive(43).pubkey()

    b = HDNode()
    b.from_master(b'1'*32)
    p2 = b.derive(43 | 0x80000000).pubkey()
    assert b.depth() == 1
    assert b.parent_fp() == m_fp
    assert p1 == p2

test_serial()
test_b39()
test_derive()

print('PASS')
