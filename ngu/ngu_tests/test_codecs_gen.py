# AUTOGEN
try:
    from base64 import b32encode, b32decode

    import pycoin.encoding.b58
    b58encode = pycoin.encoding.b58.b2a_hashed_base58
    b58decode = pycoin.encoding.b58.a2b_hashed_base58
    ngu = None
except ImportError:
    import ngu
    from ubinascii import unhexlify as a2b_hex
    b32encode = ngu.codecs.b32_encode
    b32decode = ngu.codecs.b32_decode

    b58encode = ngu.codecs.b58_encode
    b58decode = ngu.codecs.b58_decode

# len=1
assert b'l' == b32decode(b'NQ======'), "fail @ 1"
assert b'l' == b32decode(b32encode(b'l')), "fail @ 1"
# len=8
assert b'l\xf9\xa0\xe2\x89"H-' == b32decode(b'NT42BYUJEJEC2==='), "fail @ 8"
assert b'l\xf9\xa0\xe2\x89"H-' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-')), "fail @ 8"
# len=15
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa' == b32decode(b'NT42BYUJEJEC2QZWKECHASDB'), "fail @ 15"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa')), "fail @ 15"
# len=22
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2Q===='), "fail @ 22"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u')), "fail @ 22"
# len=29
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSI='), "fail @ 29"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9')), "fail @ 29"
# len=36
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSLYB3OWZ6NA4I======'), "fail @ 36"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2')), "fail @ 36"
# len=43
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSLYB3OWZ6NA4KESESBNIM3FC==='), "fail @ 43"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q')), "fail @ 43"
# len=50
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSLYB3OWZ6NA4KESESBNIM3FCBDQJBQ4EGBJ'), "fail @ 50"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)')), "fail @ 50"
# len=57
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSLYB3OWZ6NA4KESESBNIM3FCBDQJBQ4EGBJGBARE5L6BFEA===='), "fail @ 57"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH')), "fail @ 57"
# len=64
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSLYB3OWZ6NA4KESESBNIM3FCBDQJBQ4EGBJGBARE5L6BFEGBVAYZF4A5XI='), "fail @ 64"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd')), "fail @ 64"
# len=71
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSLYB3OWZ6NA4KESESBNIM3FCBDQJBQ4EGBJGBARE5L6BFEGBVAYZF4A5XLM7GQOFCJCJA======'), "fail @ 71"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H')), "fail @ 71"
# len=78
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pH' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSLYB3OWZ6NA4KESESBNIM3FCBDQJBQ4EGBJGBARE5L6BFEGBVAYZF4A5XLM7GQOFCJCJAWUGNSRARYEQ==='), "fail @ 78"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pH' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pH')), "fail @ 78"
# len=85
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12' == b32decode(b'NT42BYUJEJEC2QZWKECHASDBYIMCSMCBCJ2X4CKIMDKBRSLYB3OWZ6NA4KESESBNIM3FCBDQJBQ4EGBJGBARE5L6BFEGBVAYZF4A5XLM7GQOFCJCJAWUGNSRARYEQYOCDAUTAQIS'), "fail @ 85"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12' == b32decode(b32encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12')), "fail @ 85"
# len=1
assert b'l' == b58decode('DGRfw3a'), "fail @ 1"
assert b'l' == b58decode(b58encode(b'l')), "fail @ 1"
# len=8
assert b'l\xf9\xa0\xe2\x89"H-' == b58decode('34Gutkk57wVWUFNRM'), "fail @ 8"
assert b'l\xf9\xa0\xe2\x89"H-' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-')), "fail @ 8"
# len=15
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa' == b58decode('Lx7QsKwRzgzFXiqY7DQ5HaHwex'), "fail @ 15"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa')), "fail @ 15"
# len=22
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u' == b58decode('4LYRTgjw1jZdZMkf5owo2GQMdmhbG4hchN7W'), "fail @ 22"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u')), "fail @ 22"
# len=29
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9' == b58decode('ZNbeqFR3583HnXpaDcgxLAvZfKh6qx8JhZhtoiL2crJxz'), "fail @ 29"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9')), "fail @ 29"
# len=36
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2' == b58decode('6R43k1b4naMypUagi4MLuwm2yoGqmshDHR1qbToUVp6qhjbGo3SoLmq'), "fail @ 36"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2')), "fail @ 36"
# len=43
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q' == b58decode('uXhmz7C2Mf3rDQFD7B2fwWorv1RvCQm9TKpxETx2tWwTdEGMmkpaFLYeXrm2Y1ki'), "fail @ 43"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q')), "fail @ 43"
# len=50
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)' == b58decode('9nbqUhxWTZgUNMcWXxSXxhCvPfbZWYuGTa6fnGdz2RpC8sVXUZckg2mFBzb9dcuSNZbqKrhxot'), "fail @ 50"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)')), "fail @ 50"
# len=57
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH' == b58decode('2UEmLFRQRhtxqRR1m3gpDuapEgF74vLhyAMfK83TGKiEz2tq9Mzg4opJXRSEuvQVkZVaNwMa3nRuVUnjRZQi'), "fail @ 57"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH')), "fail @ 57"
# len=64
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd' == b58decode('FFui18PX4gcWvuJpRa8ycrWDZkHuDkWxhsmvimuptqJwbe6LfX1R76QysBs4PFbDVf9wwKW43NMe2JAA1wsnjZRpdqiRk'), "fail @ 64"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd')), "fail @ 64"
# len=71
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H' == b58decode('3PK3wFJbG2hJNjtv74AtWUj74SVTp3aGhauvsL7e9yEi9CttpqRFLVVE2wLXdDePEaJHE1iaQpHyqcBrtaxsucQj7U11q67K3wimApH'), "fail @ 71"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H')), "fail @ 71"
# len=78
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pH' == b58decode('Q8nwWFeF1HEnomUAsw1J8zUFs4gTtdMAgToN7LWwgYjQhxaAzkY5nKY9SjejEyEDaUnjVhZZcEarP9D5VvXSddLQbScq4BiMi5WXiHbZJA9n8Sqn'), "fail @ 78"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pH' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pH')), "fail @ 78"
# len=85
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12' == b58decode('4sS4hhDhzBTrQGDDZy6JhPuozauitcS761BvMnmmFt6GagpHmzGUsY5FqxfcoLYsN3GsX2eNG4NhwDoNEojavU4GBHdvrBqoNoHr9uwD17ebL4EJ9KqeY8spWW'), "fail @ 85"
assert b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12' == b58decode(b58encode(b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xddl\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12')), "fail @ 85"

if ngu:
 msg = b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd'
 assert ngu.codecs.segwit_decode('bc1qdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzprcnzfh') == ('bc', 0, msg[0:20])
 assert ngu.codecs.segwit_encode('bc', 0, msg[0:20]) == 'bc1qdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzprcnzfh'
 assert ngu.codecs.segwit_decode('bc1qdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmws0yk0md') == ('bc', 0, msg[0:32])
 assert ngu.codecs.segwit_encode('bc', 0, msg[0:32]) == 'bc1qdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmws0yk0md'
 assert ngu.codecs.segwit_decode('bc1pdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpa659p7') == ('bc', 1, msg[0:20])
 assert ngu.codecs.segwit_encode('bc', 1, msg[0:20]) == 'bc1pdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpa659p7'
 assert ngu.codecs.segwit_decode('bc1pdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmws9nkxr3') == ('bc', 1, msg[0:32])
 assert ngu.codecs.segwit_encode('bc', 1, msg[0:32]) == 'bc1pdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmws9nkxr3'
 assert ngu.codecs.segwit_decode('bc10dnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpy2pu48') == ('bc', 15, msg[0:20])
 assert ngu.codecs.segwit_encode('bc', 15, msg[0:20]) == 'bc10dnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpy2pu48'
 assert ngu.codecs.segwit_decode('bc10dnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmwsm2qepp') == ('bc', 15, msg[0:32])
 assert ngu.codecs.segwit_encode('bc', 15, msg[0:32]) == 'bc10dnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmwsm2qepp'
 assert ngu.codecs.segwit_decode('tb1qdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpf7g3jy') == ('tb', 0, msg[0:20])
 assert ngu.codecs.segwit_encode('tb', 0, msg[0:20]) == 'tb1qdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpf7g3jy'
 assert ngu.codecs.segwit_decode('tb1qdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmwscvqqpz') == ('tb', 0, msg[0:32])
 assert ngu.codecs.segwit_encode('tb', 0, msg[0:32]) == 'tb1qdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmwscvqqpz'
 assert ngu.codecs.segwit_decode('tb1pdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzphu0k6d') == ('tb', 1, msg[0:20])
 assert ngu.codecs.segwit_encode('tb', 1, msg[0:20]) == 'tb1pdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzphu0k6d'
 assert ngu.codecs.segwit_decode('tb1pdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmwsjmqfe7') == ('tb', 1, msg[0:32])
 assert ngu.codecs.segwit_encode('tb', 1, msg[0:32]) == 'tb1pdnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmwsjmqfe7'
 assert ngu.codecs.segwit_decode('tb10dnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpwv60w5') == ('tb', 15, msg[0:20])
 assert ngu.codecs.segwit_encode('tb', 15, msg[0:20]) == 'tb10dnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpwv60w5'
 assert ngu.codecs.segwit_decode('tb10dnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmwsvzkkmw') == ('tb', 15, msg[0:32])
 assert ngu.codecs.segwit_encode('tb', 15, msg[0:32]) == 'tb10dnu6pc5fyfyz6sek2yz8qjrpcgvzjvzpzf6huz2gvr2p3jtcpmwsvzkkmw'


 key_bytes = a2b_hex("3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsgyumg0"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6"
 assert ngu.codecs.nip19_decode("nsec180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsgyumg0") == key_bytes
 assert ngu.codecs.nip19_decode("npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6") == key_bytes
 key_bytes = a2b_hex("4326de5f15481588359c808d8b4df0df7aa9eef33473aabd57d08f1b68b97adc")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1gvnduhc4fq2csdvuszxckn0smaa2nmhnx3e6402h6z83k69e0twqktwj77"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1gvnduhc4fq2csdvuszxckn0smaa2nmhnx3e6402h6z83k69e0twq6a9nct"
 assert ngu.codecs.nip19_decode("nsec1gvnduhc4fq2csdvuszxckn0smaa2nmhnx3e6402h6z83k69e0twqktwj77") == key_bytes
 assert ngu.codecs.nip19_decode("npub1gvnduhc4fq2csdvuszxckn0smaa2nmhnx3e6402h6z83k69e0twq6a9nct") == key_bytes
 key_bytes = a2b_hex("7625c64502401df3fe3b6fb7647b08aaf30b47f7569d760f8d9087109b35d5f5")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1wcjuv3gzgqwl8l3md7mkg7cg4tesk3lh26whvrudjzr3pxe46h6syux3gs"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1wcjuv3gzgqwl8l3md7mkg7cg4tesk3lh26whvrudjzr3pxe46h6sg2dsw9"
 assert ngu.codecs.nip19_decode("nsec1wcjuv3gzgqwl8l3md7mkg7cg4tesk3lh26whvrudjzr3pxe46h6syux3gs") == key_bytes
 assert ngu.codecs.nip19_decode("npub1wcjuv3gzgqwl8l3md7mkg7cg4tesk3lh26whvrudjzr3pxe46h6sg2dsw9") == key_bytes
 key_bytes = a2b_hex("5b09342587a83655d50f53d672206dd1a59ad62313897672d0a53f1dd30daca1")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1tvyngfv84qm9t4g020t8ygrd6xje443rzwyhvuks55l3m5cd4jssmqs0h3"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1tvyngfv84qm9t4g020t8ygrd6xje443rzwyhvuks55l3m5cd4jsshkmw3y"
 assert ngu.codecs.nip19_decode("nsec1tvyngfv84qm9t4g020t8ygrd6xje443rzwyhvuks55l3m5cd4jssmqs0h3") == key_bytes
 assert ngu.codecs.nip19_decode("npub1tvyngfv84qm9t4g020t8ygrd6xje443rzwyhvuks55l3m5cd4jsshkmw3y") == key_bytes
 key_bytes = a2b_hex("4839eb452b9296c25ee1892848c4812009f0d9376b41a36d305aa05748c7d120")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1fqu7k3ftj2tvyhhp3y5y33ypyqylpkfhddq6xmfst2s9wjx86ysqem2vu4"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1fqu7k3ftj2tvyhhp3y5y33ypyqylpkfhddq6xmfst2s9wjx86ysq4dpd6q"
 assert ngu.codecs.nip19_decode("nsec1fqu7k3ftj2tvyhhp3y5y33ypyqylpkfhddq6xmfst2s9wjx86ysqem2vu4") == key_bytes
 assert ngu.codecs.nip19_decode("npub1fqu7k3ftj2tvyhhp3y5y33ypyqylpkfhddq6xmfst2s9wjx86ysq4dpd6q") == key_bytes
 key_bytes = a2b_hex("4f0b84e8ef11468c4ee3613f7976dfdf9ed31250f84faec1283d6526432e38fb")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1fu9cf680z9rgcnhrvylhjaklm70dxyjslp86asfg84jjvsew8rasx2hx6g"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1fu9cf680z9rgcnhrvylhjaklm70dxyjslp86asfg84jjvsew8ras2uu8ua"
 assert ngu.codecs.nip19_decode("nsec1fu9cf680z9rgcnhrvylhjaklm70dxyjslp86asfg84jjvsew8rasx2hx6g") == key_bytes
 assert ngu.codecs.nip19_decode("npub1fu9cf680z9rgcnhrvylhjaklm70dxyjslp86asfg84jjvsew8ras2uu8ua") == key_bytes
 key_bytes = a2b_hex("451cde1f53fe4a93bcb05c27288011168001e71c55edb2075ef20d6bb44f1717")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1g5wdu86nle9f809stsnj3qq3z6qqrecu2hkmyp677gxkhdz0zutspug8hl"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1g5wdu86nle9f809stsnj3qq3z6qqrecu2hkmyp677gxkhdz0zutsd2rx32"
 assert ngu.codecs.nip19_decode("nsec1g5wdu86nle9f809stsnj3qq3z6qqrecu2hkmyp677gxkhdz0zutspug8hl") == key_bytes
 assert ngu.codecs.nip19_decode("npub1g5wdu86nle9f809stsnj3qq3z6qqrecu2hkmyp677gxkhdz0zutsd2rx32") == key_bytes
 key_bytes = a2b_hex("3ab9eef38cd4fa8305d3661470fcde19f02842f599057a54e7ddb16a770756fe")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec182u7auuv6nagxpwnvc28plx7r8czssh4nyzh5488mkck5ac82mlqlh0aga"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub182u7auuv6nagxpwnvc28plx7r8czssh4nyzh5488mkck5ac82mlqnpyuwg"
 assert ngu.codecs.nip19_decode("nsec182u7auuv6nagxpwnvc28plx7r8czssh4nyzh5488mkck5ac82mlqlh0aga") == key_bytes
 assert ngu.codecs.nip19_decode("npub182u7auuv6nagxpwnvc28plx7r8czssh4nyzh5488mkck5ac82mlqnpyuwg") == key_bytes
 key_bytes = a2b_hex("e5e52edefe2fb8777e0b0f7192da9ebf3dd811a09b189d4407b073f3b7b6d869")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1uhjjahh797u8wlstpace9k57hu7asydqnvvf63q8kpel8dakmp5sw3fqnt"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1uhjjahh797u8wlstpace9k57hu7asydqnvvf63q8kpel8dakmp5sz8zp47"
 assert ngu.codecs.nip19_decode("nsec1uhjjahh797u8wlstpace9k57hu7asydqnvvf63q8kpel8dakmp5sw3fqnt") == key_bytes
 assert ngu.codecs.nip19_decode("npub1uhjjahh797u8wlstpace9k57hu7asydqnvvf63q8kpel8dakmp5sz8zp47") == key_bytes
 key_bytes = a2b_hex("b4b4a7dd295fb7831ecd1ecc7fe5ef95478c39811c84740a6b4acb6befa1446b")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1kj620hfft7mcx8kdrmx8le00j4rccwvprjz8gzntft9khmapg34sntj903"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1kj620hfft7mcx8kdrmx8le00j4rccwvprjz8gzntft9khmapg34slaeyfy"
 assert ngu.codecs.nip19_decode("nsec1kj620hfft7mcx8kdrmx8le00j4rccwvprjz8gzntft9khmapg34sntj903") == key_bytes
 assert ngu.codecs.nip19_decode("npub1kj620hfft7mcx8kdrmx8le00j4rccwvprjz8gzntft9khmapg34slaeyfy") == key_bytes
 key_bytes = a2b_hex("9783008d1659039eae645704bffc01353571531643572162821f2a9a059522ae")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1j7psprgktypeatny2uztllqpx56hz5ckgdtjzc5zru4f5pv4y2hqfve2v7"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1j7psprgktypeatny2uztllqpx56hz5ckgdtjzc5zru4f5pv4y2hq96jt2t"
 assert ngu.codecs.nip19_decode("nsec1j7psprgktypeatny2uztllqpx56hz5ckgdtjzc5zru4f5pv4y2hqfve2v7") == key_bytes
 assert ngu.codecs.nip19_decode("npub1j7psprgktypeatny2uztllqpx56hz5ckgdtjzc5zru4f5pv4y2hq96jt2t") == key_bytes
 key_bytes = a2b_hex("da158d29fc45d8fc622a34807c95a54b20ba2862d7db07c58bec49dc4c1fb68f")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1mg2c620ughv0cc32xjq8e9d9fvst52rz6lds03vta3yacnqlk68sqr99lc"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1mg2c620ughv0cc32xjq8e9d9fvst52rz6lds03vta3yacnqlk68sv4wyed"
 assert ngu.codecs.nip19_decode("nsec1mg2c620ughv0cc32xjq8e9d9fvst52rz6lds03vta3yacnqlk68sqr99lc") == key_bytes
 assert ngu.codecs.nip19_decode("npub1mg2c620ughv0cc32xjq8e9d9fvst52rz6lds03vta3yacnqlk68sv4wyed") == key_bytes
 key_bytes = a2b_hex("10a5ad1a48540d3a1b87a4379581a9262e7da16d08195ff277d1620fcd5016b5")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1zzj66xjg2sxn5xu85smetqdfych8mgtdpqv4lunh693qln2sz66sup6u9l"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1zzj66xjg2sxn5xu85smetqdfych8mgtdpqv4lunh693qln2sz66ssh3ar2"
 assert ngu.codecs.nip19_decode("nsec1zzj66xjg2sxn5xu85smetqdfych8mgtdpqv4lunh693qln2sz66sup6u9l") == key_bytes
 assert ngu.codecs.nip19_decode("npub1zzj66xjg2sxn5xu85smetqdfych8mgtdpqv4lunh693qln2sz66ssh3ar2") == key_bytes
 key_bytes = a2b_hex("5678473648054df167716c6b5252d98134525bf8006fdb3342bf5ac110a7c988")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec12euywdjgq4xlzem3d344y5kesy69yklcqphakv6zhadvzy98exyqns7xm8"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub12euywdjgq4xlzem3d344y5kesy69yklcqphakv6zhadvzy98exyqlx48aj"
 assert ngu.codecs.nip19_decode("nsec12euywdjgq4xlzem3d344y5kesy69yklcqphakv6zhadvzy98exyqns7xm8") == key_bytes
 assert ngu.codecs.nip19_decode("npub12euywdjgq4xlzem3d344y5kesy69yklcqphakv6zhadvzy98exyqlx48aj") == key_bytes
 key_bytes = a2b_hex("7d1d270b6269815c9bb3006af9a5f6d5df94e8cd46526372b56bf69076b82166")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec105wjwzmzdxq4exanqp40nf0k6h0ef6xdgefxxu44d0mfqa4cy9nq7a56yq"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub105wjwzmzdxq4exanqp40nf0k6h0ef6xdgefxxu44d0mfqa4cy9nqjtlmz4"
 assert ngu.codecs.nip19_decode("nsec105wjwzmzdxq4exanqp40nf0k6h0ef6xdgefxxu44d0mfqa4cy9nq7a56yq") == key_bytes
 assert ngu.codecs.nip19_decode("npub105wjwzmzdxq4exanqp40nf0k6h0ef6xdgefxxu44d0mfqa4cy9nqjtlmz4") == key_bytes
 key_bytes = a2b_hex("dbba94aae615e0a7b44d6c03b227e8ef07e919f06179a5c986a0a84bc283259f")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1mwaff2hxzhs20dzddspmyflgaur7jx0sv9u6tjvx5z5yhs5ryk0s5csd8w"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1mwaff2hxzhs20dzddspmyflgaur7jx0sv9u6tjvx5z5yhs5ryk0scwmvpm"
 assert ngu.codecs.nip19_decode("nsec1mwaff2hxzhs20dzddspmyflgaur7jx0sv9u6tjvx5z5yhs5ryk0s5csd8w") == key_bytes
 assert ngu.codecs.nip19_decode("npub1mwaff2hxzhs20dzddspmyflgaur7jx0sv9u6tjvx5z5yhs5ryk0scwmvpm") == key_bytes
 key_bytes = a2b_hex("6317c40ab843c230a1f5435a6979dcf7e2afcaeb915438c01eb38be12d6cc6c1")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1vvtugz4cg0prpg04gddxj7wu7l32ljhtj92r3sq7kw97zttvcmqs6u6su4"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1vvtugz4cg0prpg04gddxj7wu7l32ljhtj92r3sq7kw97zttvcmqsk2336q"
 assert ngu.codecs.nip19_decode("nsec1vvtugz4cg0prpg04gddxj7wu7l32ljhtj92r3sq7kw97zttvcmqs6u6su4") == key_bytes
 assert ngu.codecs.nip19_decode("npub1vvtugz4cg0prpg04gddxj7wu7l32ljhtj92r3sq7kw97zttvcmqsk2336q") == key_bytes
 key_bytes = a2b_hex("ced2cc757a11e6e6dea49e28ab414b78b0bbc8af2fb1f3575cd01111281963ab")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1emfvcat6z8nwdh4ync52ks2t0zcthj9097clx46u6qg3z2qevw4slp4eum"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1emfvcat6z8nwdh4ync52ks2t0zcthj9097clx46u6qg3z2qevw4snh7c6w"
 assert ngu.codecs.nip19_decode("nsec1emfvcat6z8nwdh4ync52ks2t0zcthj9097clx46u6qg3z2qevw4slp4eum") == key_bytes
 assert ngu.codecs.nip19_decode("npub1emfvcat6z8nwdh4ync52ks2t0zcthj9097clx46u6qg3z2qevw4snh7c6w") == key_bytes
 key_bytes = a2b_hex("94d88722f9fefbba0758b6f626fd6fcc7eb874d212d700fe44c2da9909a6ff40")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1jnvgwghelmam5p6ckmmzdlt0e3ltsaxjzttspljyctdfjzdxlaqquxl6fe"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1jnvgwghelmam5p6ckmmzdlt0e3ltsaxjzttspljyctdfjzdxlaqqss5m0v"
 assert ngu.codecs.nip19_decode("nsec1jnvgwghelmam5p6ckmmzdlt0e3ltsaxjzttspljyctdfjzdxlaqquxl6fe") == key_bytes
 assert ngu.codecs.nip19_decode("npub1jnvgwghelmam5p6ckmmzdlt0e3ltsaxjzttspljyctdfjzdxlaqqss5m0v") == key_bytes
 key_bytes = a2b_hex("c5c7c730c2318614d24b0108ca99cd1f5521470efb8d99bb2cab406c30d0a558")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec1chruwvxzxxrpf5jtqyyv4xwdra2jz3cwlwxenwev4dqxcvxs54vq408aj4"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub1chruwvxzxxrpf5jtqyyv4xwdra2jz3cwlwxenwev4dqxcvxs54vqeevu5q"
 assert ngu.codecs.nip19_decode("nsec1chruwvxzxxrpf5jtqyyv4xwdra2jz3cwlwxenwev4dqxcvxs54vq408aj4") == key_bytes
 assert ngu.codecs.nip19_decode("npub1chruwvxzxxrpf5jtqyyv4xwdra2jz3cwlwxenwev4dqxcvxs54vqeevu5q") == key_bytes
 key_bytes = a2b_hex("56e86f6bc18c549071cd0909719683aafbaef1599597442231b4f0cfed0fa665")
 assert ngu.codecs.nip19_encode("nsec", key_bytes) == "nsec12m5x767p332fquwdpyyhr95r4ta6au2ejkt5gg33kncvlmg05ejsnup0nk"
 assert ngu.codecs.nip19_encode("npub", key_bytes) == "npub12m5x767p332fquwdpyyhr95r4ta6au2ejkt5gg33kncvlmg05ejsl22w4r"
 assert ngu.codecs.nip19_decode("nsec12m5x767p332fquwdpyyhr95r4ta6au2ejkt5gg33kncvlmg05ejsnup0nk") == key_bytes
 assert ngu.codecs.nip19_decode("npub12m5x767p332fquwdpyyhr95r4ta6au2ejkt5gg33kncvlmg05ejsl22w4r") == key_bytes
print('PASS - test_codecs_gen.py')
