#!/usr/bin/env python3
"""
Extract NIST CAVP HMAC_DRBG (SHA-256) test vectors into a C header.

Source: drbgtestvectors.zip from csrc.nist.gov (CAVS 14.3, 2013-04-02).
Selects vectors our implementation can exercise:
  - [SHA-256] sections
  - PredictionResistance = False
  - AdditionalInputLen = 0 (generate() takes no additional input)
Personalization string, when present, is concatenated into the instantiate
seed material (entropy || nonce || personalization) per SP 800-90A 10.1.2.3.

Cross-checks every emitted vector against an independent pure-Python
HMAC_DRBG implementation (stdlib hmac) before writing the header.
"""

import hmac as pyhmac
import hashlib
import re
import sys


def parse_rsp(path):
    """Yield dicts of vector fields from SHA-256 / AdditionalInputLen=0 blocks."""
    section = None
    params = {}
    cur = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            m = re.match(r'\[(.+?)\]$', line)
            if m:
                inner = m.group(1)
                if '=' in inner:
                    k, v = [x.strip() for x in inner.split('=', 1)]
                    params[k] = v
                else:
                    section = inner
                    params = {}
                continue
            k, _, v = [x.strip() for x in line.partition('=')]
            if k == 'COUNT':
                cur = {'params': dict(params), 'section': section, 'COUNT': v}
                continue
            if cur is None:
                continue
            # AdditionalInput appears twice (one per generate call)
            if k in cur:
                k2 = k + '2'
                assert k2 not in cur
                cur[k2] = v
            else:
                cur[k] = v
            if k == 'ReturnedBits':
                if (cur['section'] == 'SHA-256'
                        and cur['params']['AdditionalInputLen'] == '0'):
                    yield cur
                cur = None


class RefHmacDrbg:
    """Independent SP 800-90A 10.1.2 reference (SHA-256)."""

    def __init__(self, seed_material):
        self.K = b'\x00' * 32
        self.V = b'\x01' * 32
        self._update(seed_material)

    def _hmac(self, data):
        return pyhmac.new(self.K, data, hashlib.sha256).digest()

    def _update(self, data):
        self.K = self._hmac(self.V + b'\x00' + data)
        self.V = self._hmac(self.V)
        if data:
            self.K = self._hmac(self.V + b'\x01' + data)
            self.V = self._hmac(self.V)

    def reseed(self, seed_material):
        self._update(seed_material)

    def generate(self, n):
        out = b''
        while len(out) < n:
            self.V = self._hmac(self.V)
            out += self.V
        self._update(b'')
        return out[:n]


def check(vec):
    seed = bytes.fromhex(vec['EntropyInput'] + vec['Nonce']
                         + vec.get('PersonalizationString', ''))
    ref = RefHmacDrbg(seed)
    if 'EntropyInputReseed' in vec:
        ref.reseed(bytes.fromhex(vec['EntropyInputReseed']))
    want = bytes.fromhex(vec['ReturnedBits'])
    ref.generate(len(want))
    got = ref.generate(len(want))
    return got == want


def c_bytes(hexstr):
    return '"' + ''.join('\\x%s' % hexstr[i:i + 2]
                         for i in range(0, len(hexstr), 2)) + '"'


def emit(vectors, out):
    out.write('''\
// AUTO-GENERATED from NIST CAVP drbgtestvectors.zip (CAVS 14.3, 2013-04-02)
// https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program
// HMAC_DRBG [SHA-256], PredictionResistance=False, AdditionalInputLen=0.
// Seed material = EntropyInput || Nonce || PersonalizationString.
// ReturnedBits is the output of the SECOND generate call.
// The trailing "derived" entries cover short/partial-block outputs (no CAVP
// coverage exists); they come from an independent reference implementation
// that the official vectors above validate.
// Regenerate with gen_hmac_drbg_vectors.py from the CAVP zip; no hand edits.

typedef struct {
    const char *file;           // CAVP source file + COUNT
    const uint8_t *seed;        // instantiate seed material
    size_t      seed_len;
    const uint8_t *reseed;      // NULL if no reseed step
    size_t      reseed_len;
    const uint8_t *expect;      // second generate() output
    size_t      expect_len;
} cavp_vector_t;

''')
    entries = []
    for i, v in enumerate(vectors):
        seed = v['EntropyInput'] + v['Nonce'] + v.get('PersonalizationString', '')
        rs = v.get('EntropyInputReseed')
        rb = v['ReturnedBits']
        name = '%s COUNT=%s (PSLen=%s)' % (
            v['file'], v['COUNT'], v['params']['PersonalizationStringLen'])
        out.write('static const uint8_t seed_%d[] = %s;\n' % (i, c_bytes(seed)))
        if rs:
            out.write('static const uint8_t reseed_%d[] = %s;\n' % (i, c_bytes(rs)))
        out.write('static const uint8_t expect_%d[] = %s;\n' % (i, c_bytes(rb)))
        entries.append('    { "%s", seed_%d, %d, %s, %d, expect_%d, %d },' % (
            name, i, len(seed) // 2,
            ('reseed_%d' % i) if rs else 'NULL', (len(rs) // 2) if rs else 0,
            i, len(rb) // 2))
    out.write('\nstatic const cavp_vector_t CAVP_VECTORS[] = {\n')
    out.write('\n'.join(entries))
    out.write('\n};\n')


def derived_kats():
    """All CAVP outputs are 128 bytes; the short/partial-block generate path
    (used by uint32() and uniform() on every call) needs its own KATs. These
    are derived from the reference implementation above, which the official
    vectors validate."""
    kats = []
    for n in (4, 33):
        seed = bytes(range(48))
        ref = RefHmacDrbg(seed)
        ref.generate(n)
        kats.append({
            'file': 'derived', 'COUNT': 'len=%d' % n,
            'params': {'PersonalizationStringLen': '0'},
            'EntropyInput': seed.hex(), 'Nonce': '',
            'ReturnedBits': ref.generate(n).hex(),
        })
    return kats


def main():
    picked = []
    for fname, tag in [('no_reseed/HMAC_DRBG.rsp', 'no_reseed'),
                       ('pr_false/HMAC_DRBG.rsp', 'pr_false')]:
        by_cfg = {}
        for vec in parse_rsp(fname):
            vec['file'] = tag
            cfg = vec['params']['PersonalizationStringLen']
            by_cfg.setdefault(cfg, []).append(vec)
        # first 3 vectors of each personalization-length config
        for cfg in sorted(by_cfg):
            picked += by_cfg[cfg][:3]

    for v in picked:
        assert check(v), 'reference mismatch: %s COUNT=%s' % (v['file'], v['COUNT'])
    print('cross-checked %d vectors against pure-python reference: OK' % len(picked))
    picked += derived_kats()

    with open(sys.argv[1], 'w') as f:
        emit(picked, f)
    print('wrote', sys.argv[1])


if __name__ == '__main__':
    main()
