#!/bin/sh
# 
try:
    # make the test
    from mnemonic import Mnemonic

    eng = Mnemonic('english')

    with open('b39-data.txt', 'wt') as fd:
        for ln in [16, 20, 24, 28, 32]:
            for val in [b'\0', b'\xff', b'\xab\xcd', b'\xa5\xa5', b'\xAA', b'\x55']:
                vector = val * (ln // len(val))
                exp = eng.to_mnemonic(vector)
                print('(%r, %r)' % (vector, exp), file=fd)

except:
    import bip39

    # run the test
    for ln in open('b39-data.txt', 'rt').readlines():
        #print(ln)
        vector, expect = eval(ln)

        ans = bip39.b2a_words(vector)
        assert ans == expect, "(got) %r != (expected) %r " % (ans, expect)

    print('PASS')
