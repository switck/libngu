# Desktop only: make test vectors
import pyaes

rnd = b'\xa3;\x0c\xe8y\x18d\x82\x08S\xca=\x10\x8f\xb2?\xd9\xe5~\x05\x06>SC\x84q\t\x050\xf1{!'
rmsg = b'\xe0\xef\xda\xd2L\x1a\x13\x8a\x1c3\xd6n\xd3\xfe\x0e"\x05\x14\xce\x82\xfd\xeb\xf5S N\x81\x95\xc1\xf2#\xe4'
iv = b'\x1c\x145U\x88A\xf4N\xab\xd9\xd6\xd7\xc0\xa8\xa7\x10'

with open('test_aes_gen.py', 'wt') as fd:
    print('''# AUTOGEN
import ngu
AES = ngu.aes
''', file=fd)

    for ksize in [16, 24, 32]:
        key = rnd[0:ksize]
        msg = rmsg[0:16]
        print(f'\n# len={ksize}', file=fd)

        expect = pyaes.AESModeOfOperationCBC(key, iv).encrypt(msg)
        print(f'assert AES.CBC(True, {key!r}, {iv!r}).cipher({msg!r}) == {expect!r}', file=fd)
        print(f'assert AES.CBC(False, {key!r}, {iv!r}).cipher({expect!r}) == {msg!r}', file=fd)

        expect = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(0)).encrypt(msg)
        print(f'assert AES.CTR({key!r}, bytes(16)).cipher({msg!r}) == {expect!r}', file=fd)
        print(f'assert AES.CTR({key!r}, bytes(16)).cipher({expect!r}) == {msg!r}', file=fd)

        mlen = 1023
        expect = pyaes.AESModeOfOperationCTR(key, pyaes.Counter(0)).encrypt(bytes(mlen))
        print(f'assert AES.CTR({key!r}, bytes(16)).cipher(bytes({mlen}))[-8:] == {expect[-8:]!r}', file=fd)
        print(f'assert AES.CTR({key!r}, bytes(16)).cipher({expect!r}) == bytes({mlen})', file=fd)

    print("print('PASS - %s')" % fd.name, file=fd)

    print("run code now in: %s" % fd.name)

print('PASS - test_aes')
