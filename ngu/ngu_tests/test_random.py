
import ngu

for trial in range(100):
    v = [ngu.random.uint32() for i in range(1000)]
    assert len(v) == len(set(v)), 'bad luck, try again'
    assert max(v) > 0x80000000
    assert min(v) < 0x80000000

for ln in range(1, 700):
    b = ngu.random.bytes(ln)
    assert len(b) == ln

for trial in range(100):
    b = ngu.random.bytes(4096)
    assert min(b) < 0x10
    assert max(b) > 0xe0

for trial in range(1000):
    b = ngu.random.uniform(100)
    assert 0 <= b < 100

for mx in range(10, 2000, 73):
    print("test: uniform[0 ..%3d)" % mx, end='')
    got = set()
    for nsamples in range(mx*10):
        b = ngu.random.uniform(mx)
        got.add(b)
    covered = (len(got)*100.0/mx)
    print(" => %.0f %%" % covered)
    assert covered >= 97        # maybe bad luck

# api test only; can't verify results (public output is XOR-masked with the
# chip TRNG, so the reseeded Yasmarang stream is not observable from here)
ngu.random.reseed(123)                       # legacy int arg still accepted
ngu.random.reseed(456)
ngu.random.reseed(0xffff_ffff)

# regression: reseed() must accept a full-width (digest) seed, not just 32 bits.
# The historic bug fed only n[0:4] into reseed(); guard that the full digest is
# a valid argument so a caller can hand over all of its entropy.
ngu.random.reseed(bytes(range(32)))          # 32-byte digest (bytes)
ngu.random.reseed(bytearray(b'\xa5' * 32))   # bytes-like (bytearray)
ngu.random.reseed(b'\x01\x02\x03\x04\x05\x06\x07\x08')   # SE-sized minimum
# an empty seed must be rejected, not silently ignored (no-op reseed)
try:
    ngu.random.reseed(b'')
    raise AssertionError('empty seed was accepted')
except ValueError:
    pass
# generator keeps producing well-distributed output after a full-width reseed
after = [ngu.random.uint32() for _ in range(1000)]
assert len(after) == len(set(after)), 'bad luck, try again'
assert max(after) > 0x80000000 and min(after) < 0x80000000

print('PASS - test_random')
