from binascii import b2a_hex

try:
    import ngu
    sha512 = ngu.hash.sha512
    ripemd160 = ngu.hash.ripemd160
    double_sha256 = ngu.hash.double_sha256
except:
    import hashlib
    from hashlib import sha512, sha256
    ripemd160 = lambda x=b'': hashlib.new('ripemd160', x)
    double_sha256 = lambda x: sha256(sha256(x).digest()).digest()

def expect(func, msg, dig):
    assert str(b2a_hex(func(msg).digest()), 'ascii') == dig

    for sz in range(1, max(99, len(msg))):
        md = func()
        for pos in range(0, len(msg), sz):
            md.update(msg[pos:pos+sz])
        assert str(b2a_hex(md.digest()), 'ascii') == dig


expect(sha512, b'', 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e')
expect(sha512, b'abc', 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f')
expect(sha512, b'abc'*99, 'be0a8f07e572e068306b19fa0750f3cc6a11b5f0e0cf02ae7c944c9314be97ca4c8fb14e9c806a86aa40682a2688f63355879509a323d2896b45658a9f7f3755')
expect(sha512,
    b'abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu',
    '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909')


expect(ripemd160, b'', '9c1185a5c5e9fc54612808977ee8f548b2258d31')
expect(ripemd160, b'abc', '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc')
expect(ripemd160, b'bbb'*98, '4702172ecf600a721971b351da0b69b460e3f160')
expect(ripemd160, b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 'b0e20b6e3116640286ed3a87a5713079b21f5189')

assert double_sha256(b'') == b']\xf6\xe0\xe2v\x13Y\xd3\n\x82u\x05\x8e)\x9f\xcc\x03\x81SEE\xf5\\\xf4>A\x98?]L\x94V'
assert double_sha256(b'ab'*77) == b'\x9c\xaag \xedA\xfb\xa7\xab\x8c+p\xa9\xa6\xd4\xc9\x80\x99b5\xa3\xab\xa3\x19\xdd|\x876w\x0e\xfd\xaf'


print('PASS')
