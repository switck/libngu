import sys

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

            cc = w.bip32_key_get_chain_code(node)
            xprv = w.base58check_from_bytes(w.bip32_key_serialize(node, 0))
            xpub = w.base58check_from_bytes(w.bip32_key_serialize(node, w.BIP32_FLAG_KEY_PUBLIC))
            addr = w.bip32_key_to_address(node, w.WALLY_ADDRESS_TYPE_P2PKH, 0)
            print("  a = HDNode(); a.from_master(%r)" % ms, file=fd)
            print("  assert a.pubkey() == %r" % pub, file=fd)
            print("  assert a.privkey() == %r" % priv, file=fd)
            print("  assert a.my_fp() == 0x%s" % fp.hex(), file=fd)
            print("  assert a.chain_code() == %r" % bytes(cc), file=fd)
            print("  assert a.serialize(0x488ade4, 1) == %r" % xprv, file=fd)
            print("  assert a.serialize(0x488b21e, 0) == %r" % xpub, file=fd)
            print("  assert a.addr_help(0) == %r" % addr, file=fd)
            print("  ", file=fd)

        print("gc.collect()", file=fd)
        print("print('PASS - %s')" % fd.name, file=fd)
        print("run code now in: %s" % fd.name)

    sys.exit(0)
except ImportError: 
    sys.path.insert(0, '')      # bugfix
    pass

V_XPRV = 0x0488ade4
V_XPUB = 0x0488b21e

from ubinascii import unhexlify as a2b_hex

import ngu, gc
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
    import bip39
    from . import b39_vectors

    for raw, words, ms, xprv in b39_vectors.english:
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
    p1 = a.derive(43, False).pubkey()

    b = HDNode()
    assert b.deserialize(a.serialize(0x123, 0)) == 0x123
    p2 = b.pubkey()
    assert b.depth() == 1
    assert b.parent_fp() == m_fp
    assert p1 == p2

    c = b.copy()
    assert c != b
    assert c.pubkey() == b.pubkey()

def test_misc():
    a = HDNode()
    a.from_master(b'1'*32)
    a.derive(234234, False)

    b = HDNode().from_chaincode_privkey(a.chain_code(), a.privkey())
    a.censor()
    assert a.serialize(0x123, 0) == b.serialize(0x123, 0)
    assert a.serialize(0x123, 1) == b.serialize(0x123, 1)

def test_vectors():

    pub = 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8'
    prv = 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'
    m = HDNode()
    assert m.deserialize(prv) == V_XPRV
    assert m.serialize(V_XPUB, 0) == pub
    assert m.pubkey() == HDNode().from_master(a2b_hex('000102030405060708090a0b0c0d0e0f')).pubkey()

    # m/0'
    d = m.copy()
    d.derive(0, True)
    assert d.depth() == 1
    assert d.serialize(V_XPUB, 0) == 'xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw'
    assert d.serialize(V_XPRV, 1) == 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7'

    # m/0'/1
    d = m.copy()
    d.derive(0, True)
    d.derive(1, False)
    assert d.depth() == 2
    assert d.serialize(V_XPUB, 0) == 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ'
    assert d.serialize(V_XPRV, 1) == 'xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs'

    # m/0'/1/2'
    d.derive(2, True)
    assert d.depth() == 3
    assert d.serialize(V_XPUB, 0) == 'xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5'
    assert d.serialize(V_XPRV, 1) == 'xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM'
    
    # m/0'/1/2'/2
    d.derive(2, False)
    assert d.depth() == 4
    assert d.serialize(V_XPUB, 0) == 'xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV'
    assert d.serialize(V_XPRV, 1) == 'xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334'

    # m/0'/1/2'/2/1000000000
    d.derive(1000000000, False)
    assert d.depth() == 5
    assert d.serialize(V_XPUB, 0) == 'xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy'
    assert d.serialize(V_XPRV, 1) == 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76'

    # Test Vector 2
    m = HDNode()
    m.from_master(a2b_hex('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542'))
    assert m.serialize(V_XPUB, 0) == 'xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB'
    assert m.serialize(V_XPRV, 1) == 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U'

    for sk, hard, xpub, xprv in [
        (0, False, 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH', 'xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt'),
        (2147483647, True, 'xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a', 'xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9'),
        (1, False, 'xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon', 'xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef'),
        (2147483646, True, 'xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL', 'xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc'),
        (2, False, 'xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt', 'xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j'),
    ]:
        m.derive(sk, hard)
        assert m.serialize(V_XPUB, 0) == xpub
        assert m.serialize(V_XPRV, 1) == xprv
    assert m.depth() == 5

    # Test Vector 3
    m = HDNode()
    m.from_master(a2b_hex('4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be'))
    assert m.serialize(V_XPUB, 0) == 'xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13'
    assert m.serialize(V_XPRV, 1) == 'xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6'

    m.derive(0, 1)
    assert m.serialize(V_XPUB, 0) == 'xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y'
    assert m.serialize(V_XPRV, 1) == 'xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L'

def test_addrs():
    m = HDNode()
    m.from_master(b'1'*32)
    m.derive(34, False).derive(34, False)

    assert m.addr_help(0)[0] == '1'
    assert len(m.addr_help()) == 20

test_serial()
test_b39()
test_vectors()
test_derive()
test_addrs()
test_misc()

gc.collect()

try:
    assert False
    raise ValueError("FAIL -- asserts off")
except AssertionError:
    pass
    

print('PASS - test_hdnode')
