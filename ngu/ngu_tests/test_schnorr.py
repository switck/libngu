import ngu
from ubinascii import unhexlify


if not hasattr(ngu.secp256k1, 'sign_schnorr'):
    print('SKIP - test_schnorr: not compiled in (NGU_INCL_SCHNORR=0)')
else:
    for i in range(10):
        # random keypair
        kp = ngu.secp256k1.keypair()
        xonly_pub = kp.xonly_pubkey()
        parity = xonly_pub.parity()
        assert parity in (0, 1)
        # serialization
        xonly_pub_bytes = xonly_pub.to_bytes()
        # parsing
        xonly_pub_clone = ngu.secp256k1.xonly_pubkey(xonly_pub_bytes)
        assert xonly_pub_clone.to_bytes() == xonly_pub_bytes
        # random msg
        msg = ngu.random.bytes(32)
        msg_hash = ngu.hash.sha256t(b"ngu_tests", msg)
        aux_rand = ngu.random.bytes(32)
        sig_kp = ngu.secp256k1.sign_schnorr(kp, msg_hash, aux_rand)
        sig_raw = ngu.secp256k1.sign_schnorr(kp.privkey(), msg_hash, aux_rand)
        assert sig_kp == sig_raw
        assert ngu.secp256k1.verify_schnorr(sig_kp, msg_hash, kp.xonly_pubkey())

    try:
        # invalid pubkey type, has to be xonly pubkey (not classic pubkey)
        ngu.secp256k1.verify_schnorr(ngu.random.bytes(64), msg_hash, kp.pubkey())
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "xonly pubkey type"

    try:
        from b340_vectors import vectors
    except ImportError:
        from ngu_tests.b340_vectors import vectors

    for seckey, xonly_pub, aux_rand, msg, sig, ok in vectors:
        if seckey:
            seckey = unhexlify(seckey)
        if aux_rand:
            aux_rand = unhexlify(aux_rand)

        xonly_pub = unhexlify(xonly_pub)
        msg = unhexlify(msg)
        sig = unhexlify(sig)

        if seckey and aux_rand:
            # signing and verification
            assert sig == ngu.secp256k1.sign_schnorr(seckey, msg, aux_rand)
            assert ngu.secp256k1.verify_schnorr(
                sig, msg, ngu.secp256k1.xonly_pubkey(xonly_pub))
        else:
            # verification
            if ok:
                assert ngu.secp256k1.verify_schnorr(
                    sig, msg, ngu.secp256k1.xonly_pubkey(xonly_pub))
            else:
                # must raise
                try:
                    ngu.secp256k1.verify_schnorr(
                        sig, msg, ngu.secp256k1.xonly_pubkey(xonly_pub))
                    assert False  # MUST not get here
                except ValueError:
                    pass

    print('PASS - test_schnorr')
