
import ngu

for trial in range(100):
    v = [ngu.random.uint32() for i in range(1000)]
    assert len(v) == len(set(v))
    assert max(v) > 0x80000000
    assert min(v) < 0x80000000

for ln in range(1, 700):
    b = ngu.random.bytes(ln)
    assert len(b) == ln

for trial in range(100):
    b = ngu.random.bytes(4096)
    assert min(b) < 0x10
    assert max(b) > 0xe0

print('PASS - test_random')
