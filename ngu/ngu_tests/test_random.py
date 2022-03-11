
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

# api test only; can't verify results
ngu.random.reseed(123)
ngu.random.reseed(456)
ngu.random.reseed(0xffff_ffff)

print('PASS - test_random')
