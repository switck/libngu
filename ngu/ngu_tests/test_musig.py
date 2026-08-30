import ngu


if not hasattr(ngu.secp256k1, 'musig_pubkey_agg'):
    print('SKIP - test_musig: not compiled in (NGU_INCL_MUSIG=0)')
else:
    msg = 32*b"b"
    tweak_bip32 = 32*b"a"
    xonly_tweak = 32*b"c"

    signers = []
    for i in range(10):
        kp = ngu.secp256k1.keypair()
        signers.append(kp)

    signer_pubkeys = [s.pubkey() for s in signers]

    # 1st round
    sec_rands = []
    pubnonces = []
    agg_keys = set()
    agg_der_keys = set()
    for kp in signers:
        kac = ngu.secp256k1.MusigKeyAggCache()

        # not possible to get aggregate key from cache before aggregation happens
        try:
            x = kac.agg_pubkey()
            raise RuntimeError
        except ValueError:
            pass

        agg_xonly = ngu.secp256k1.musig_pubkey_agg(signer_pubkeys, kac)

        # ability to get proper non-xonly aggregate pubkey
        agg_non_xonly = kac.agg_pubkey()
        assert agg_non_xonly.to_xonly().to_bytes() == agg_xonly.to_bytes()
        agg_keys.add(agg_non_xonly.to_bytes())

        # key aggregation cache is optional, if user does not intend to sign
        agg_xonly1 = ngu.secp256k1.musig_pubkey_agg(signer_pubkeys, None)
        assert agg_xonly.to_bytes() == agg_xonly1.to_bytes()

        # without sorting (that happens by default) - aggregate key will be different
        agg_xonly2 = ngu.secp256k1.musig_pubkey_agg(signer_pubkeys, None, False)
        assert agg_xonly2.to_bytes() != agg_xonly.to_bytes()

        tweaked_pk1 = ngu.secp256k1.musig_pubkey_xonly_tweak_add(kac, xonly_tweak)
        assert isinstance(tweaked_pk1, ngu.secp256k1.pubkey)

        tweaked_pk = ngu.secp256k1.musig_pubkey_ec_tweak_add(kac, tweak_bip32)
        assert isinstance(tweaked_pk, ngu.secp256k1.pubkey)

        agg_der_keys.add(kac.agg_pubkey().to_bytes())

        sec_rand = ngu.random.bytes(32)
        sec_rands.append(sec_rand)
        pk = kp.pubkey()
        # only required argument here is pubkey (first argument)
        sn, pn = ngu.secp256k1.musig_nonce_gen(pk)
        # musig_nonce_gen uses RNG for secrand if secrand is not provided (safest way)
        sn, pn = ngu.secp256k1.musig_nonce_gen(pk, sec_rand)
        # the optional secret key MUST correspond to the pubkey used for signing
        sn, pn = ngu.secp256k1.musig_nonce_gen(pk, sec_rand, kp.privkey())
        # extra randomness for nonce derivation; uninitialized key agg cache is invalid
        sn, pn = ngu.secp256k1.musig_nonce_gen(
            pk, sec_rand, kp.privkey(), msg, None, ngu.random.bytes(32))
        # optionally the message can be added if already known
        sn, pn = ngu.secp256k1.musig_nonce_gen(pk, sec_rand, kp.privkey(), msg)

        pubnonce_bytes = pn.to_bytes()
        assert len(pubnonce_bytes) == 66
        pn1 = ngu.secp256k1.MusigPubNonce(pubnonce_bytes)
        assert pn1.to_bytes() == pubnonce_bytes
        pubnonces.append(pn)

    assert len(agg_keys) == 1
    assert len(agg_der_keys) == 1

    # 2nd round
    partial_signatures = []
    sessions = []
    agg_nonces = set()
    for kp, sr, pn in zip(signers, sec_rands, pubnonces):
        # re-initialize the cache
        kac = ngu.secp256k1.MusigKeyAggCache()
        ngu.secp256k1.musig_pubkey_agg(signer_pubkeys, kac)
        ngu.secp256k1.musig_pubkey_xonly_tweak_add(kac, xonly_tweak)
        ngu.secp256k1.musig_pubkey_ec_tweak_add(kac, tweak_bip32)
        assert kac.agg_pubkey().to_bytes() == list(agg_der_keys)[0]
        sn, pn_target = ngu.secp256k1.musig_nonce_gen(
            kp.pubkey(), sr, kp.privkey(), msg)
        assert pn.to_bytes() == pn_target.to_bytes()

        # aggregate pubnonces
        aggnonce = ngu.secp256k1.musig_nonce_agg(pubnonces)
        aggnonce_bytes = aggnonce.to_bytes()
        an1 = ngu.secp256k1.MusigAggNonce(aggnonce_bytes)
        assert an1.to_bytes() == aggnonce_bytes
        agg_nonces.add(aggnonce_bytes)

        session = ngu.secp256k1.musig_nonce_process(aggnonce, msg, kac)
        sessions.append(session)

        cleared_sn, _ = ngu.secp256k1.musig_nonce_gen(kp.pubkey())
        cleared_sn.clear()
        try:
            ngu.secp256k1.musig_partial_sign(cleared_sn, kp, kac, session)
            raise RuntimeError
        except ValueError:
            pass

        partial_signature = ngu.secp256k1.musig_partial_sign(sn, kp, kac, session)

        # re-sign with the same secnonce causes error
        try:
            ngu.secp256k1.musig_partial_sign(sn, kp, kac, session)
            raise RuntimeError
        except ValueError:
            pass

        part_sig_bytes = partial_signature.to_bytes()
        assert ngu.secp256k1.MusigPartSig(part_sig_bytes).to_bytes() == part_sig_bytes

        assert partial_signature.verify(pn_target, kp.pubkey(), kac, session)

        partial_signatures.append(partial_signature)

    assert len(agg_nonces) == 1

    for user_session in sessions:
        agg_sig = ngu.secp256k1.musig_partial_sig_agg(
            partial_signatures, user_session)
        assert len(agg_sig) == 64

        # verify aggregate signature against aggregate tweaked pubkey
        target_pk = ngu.secp256k1.pubkey(list(agg_der_keys)[0])
        assert ngu.secp256k1.verify_schnorr(
            agg_sig, msg, target_pk.to_xonly())

    # musig type checks
    kp = ngu.secp256k1.keypair()
    xonly_pk = kp.xonly_pubkey()
    pubkey = kp.pubkey()
    keyagg_cache = ngu.secp256k1.MusigKeyAggCache()
    bytes32 = ngu.random.bytes(32)
    fake_keyagg_cache = ngu.random.bytes(197)
    fake_nonce = ngu.random.bytes(132)
    fake_session = ngu.random.bytes(133)
    keyagg_cache = ngu.secp256k1.MusigKeyAggCache()
    # valid nonces below
    sn, pn = ngu.secp256k1.musig_nonce_gen(pubkey)

    try:
        # pubkey list contains xonly keys - not classic pubkey
        ngu.secp256k1.musig_pubkey_agg([xonly_pk, xonly_pk])
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "pubkeys: pubkey type"

    try:
        # key agg cache is wrong type
        ngu.secp256k1.musig_pubkey_agg([pubkey, pubkey], fake_keyagg_cache)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "key aggregation cache type"

    try:
        ngu.secp256k1.musig_pubkey_xonly_tweak_add(fake_keyagg_cache, bytes32)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "key aggregation cache type"

    try:
        ngu.secp256k1.musig_pubkey_ec_tweak_add(xonly_pk, bytes32)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "key aggregation cache type"

    for data in [kp.xonly_pubkey(), ngu.random.bytes(33)]:
        try:
            # not classic pubkey
            ngu.secp256k1.musig_nonce_gen(data)
            raise RuntimeError
        except TypeError as e:
            assert str(e) == "pubkey type"

    try:
        ngu.secp256k1.musig_nonce_gen(
            pubkey, bytes32, kp.privkey(), bytes32,
            fake_keyagg_cache, bytes32)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "key aggregation cache type"

    for pnonces in [[pubkey, xonly_pk], [fake_nonce, fake_nonce]]:
        try:
            ngu.secp256k1.musig_nonce_agg(pnonces)
            raise RuntimeError
        except TypeError as e:
            assert str(e) == "pubnonces: pubnonce type"

    try:
        ngu.secp256k1.musig_nonce_process(fake_nonce, msg, keyagg_cache)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "aggnonce type"

    try:
        ngu.secp256k1.musig_nonce_process(aggnonce, msg, fake_keyagg_cache)
        raise RuntimeError
    except TypeError as e:
        assert str(e) == "key aggregation cache type"

    for data in [
        ((pn, kp, keyagg_cache, fake_session), "secnonce type"),
        ((sn, pubkey, keyagg_cache, fake_session), "keypair type"),
        ((sn, kp, fake_keyagg_cache, fake_session), "key aggregation cache type"),
        ((sn, kp, keyagg_cache, fake_session), "session type"),
    ]:
        args = data[0]
        err = data[1]
        try:
            ngu.secp256k1.musig_partial_sign(*args)
            raise RuntimeError
        except TypeError as e:
            assert str(e) == err

    for data in [
        ((sn, pubkey, keyagg_cache, fake_session), "pubnonce type"),
        ((pn, xonly_pk, keyagg_cache, fake_session), "pubkey type"),
        ((pn, pubkey, fake_keyagg_cache, fake_session), "key aggregation cache type"),
        ((pn, pubkey, keyagg_cache, fake_session), "session type"),
    ]:
        args = data[0]
        err = data[1]
        try:
            partial_signatures[0].verify(*args)
            raise RuntimeError
        except TypeError as e:
            assert str(e) == err

    for data in [
        (([bytes32, bytes32], fake_session), "part_sigs: part sig type"),
        (([xonly_pk, pubkey], fake_session), "part_sigs: part sig type"),
        ((partial_signatures, fake_session), "session type"),
    ]:
        args = data[0]
        err = data[1]
        try:
            ngu.secp256k1.musig_partial_sig_agg(*args)
            raise RuntimeError
        except TypeError as e:
            assert str(e) == err, str(e)

    print('PASS - test_musig')
