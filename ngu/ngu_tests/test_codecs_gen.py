# AUTOGEN
try:
    from base64 import b32encode, b32decode

    import pycoin.encoding.b58
    b58encode = pycoin.encoding.b58.b2a_hashed_base58
    b58decode = pycoin.encoding.b58.a2b_hashed_base58
    ngu = None
except ImportError:
    import ngu
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
print('PASS - test_codecs_gen.py')
