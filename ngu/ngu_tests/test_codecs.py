# Desktop only: make test vectors
from base64 import b32encode, b32decode
import pycoin.encoding.b58
b58encode = pycoin.encoding.b58.b2a_hashed_base58
b58decode = pycoin.encoding.b58.a2b_hashed_base58

import sys
sys.path.append('../../libs/bech32/ref/python')
import segwit_addr

pat = b'l\xf9\xa0\xe2\x89"H-C6Q\x04pHa\xc2\x18)0A\x12u~\tH`\xd4\x18\xc9x\x0e\xdd'

with open('test_codecs_gen.py', 'wt') as fd:
    print('''# AUTOGEN
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
''', file=fd)

    for code in ['b32', 'b58']:
        for ln in range(1, 90, 7):
            vector = (pat*(1+(ln//32)))[0:ln]
            enc = eval(f'{code}encode(vector)')
            print(f'# len={ln}', file=fd)
            print(f'assert {vector!r} == {code}decode({enc!r}), "fail @ {ln}"', file=fd)
            print(f'assert {vector!r} == {code}decode({code}encode({vector!r})), "fail @ {ln}"', file=fd)


    print(f'\nif ngu:\n msg = {pat!r}', file=fd)
    for hrp in ['bc', 'tb']:
        for ver in [0, 1, 15]:
            for alen in [20, 32]:
                msg = pat[:alen]
                exp = segwit_addr.encode(hrp, ver, msg)
                print(f' assert ngu.codecs.segwit_decode({exp!r}) == ({hrp!r}, {ver}, msg[0:{alen}])', file=fd)
                print(f' assert ngu.codecs.segwit_encode({hrp!r}, {ver}, msg[0:{alen}]) == {exp!r}', file=fd)

    nip19_test_vectors = [
        ('3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d',
         'nsec180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsgyumg0',
         'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6'),
        ('4326de5f15481588359c808d8b4df0df7aa9eef33473aabd57d08f1b68b97adc',
         'nsec1gvnduhc4fq2csdvuszxckn0smaa2nmhnx3e6402h6z83k69e0twqktwj77',
         'npub1gvnduhc4fq2csdvuszxckn0smaa2nmhnx3e6402h6z83k69e0twq6a9nct'),
        ('7625c64502401df3fe3b6fb7647b08aaf30b47f7569d760f8d9087109b35d5f5',
         'nsec1wcjuv3gzgqwl8l3md7mkg7cg4tesk3lh26whvrudjzr3pxe46h6syux3gs',
         'npub1wcjuv3gzgqwl8l3md7mkg7cg4tesk3lh26whvrudjzr3pxe46h6sg2dsw9'),
        ('5b09342587a83655d50f53d672206dd1a59ad62313897672d0a53f1dd30daca1',
         'nsec1tvyngfv84qm9t4g020t8ygrd6xje443rzwyhvuks55l3m5cd4jssmqs0h3',
         'npub1tvyngfv84qm9t4g020t8ygrd6xje443rzwyhvuks55l3m5cd4jsshkmw3y'),
        ('4839eb452b9296c25ee1892848c4812009f0d9376b41a36d305aa05748c7d120',
         'nsec1fqu7k3ftj2tvyhhp3y5y33ypyqylpkfhddq6xmfst2s9wjx86ysqem2vu4',
         'npub1fqu7k3ftj2tvyhhp3y5y33ypyqylpkfhddq6xmfst2s9wjx86ysq4dpd6q'),
        ('4f0b84e8ef11468c4ee3613f7976dfdf9ed31250f84faec1283d6526432e38fb',
         'nsec1fu9cf680z9rgcnhrvylhjaklm70dxyjslp86asfg84jjvsew8rasx2hx6g',
         'npub1fu9cf680z9rgcnhrvylhjaklm70dxyjslp86asfg84jjvsew8ras2uu8ua'),
        ('451cde1f53fe4a93bcb05c27288011168001e71c55edb2075ef20d6bb44f1717',
         'nsec1g5wdu86nle9f809stsnj3qq3z6qqrecu2hkmyp677gxkhdz0zutspug8hl',
         'npub1g5wdu86nle9f809stsnj3qq3z6qqrecu2hkmyp677gxkhdz0zutsd2rx32'),
        ('3ab9eef38cd4fa8305d3661470fcde19f02842f599057a54e7ddb16a770756fe',
         'nsec182u7auuv6nagxpwnvc28plx7r8czssh4nyzh5488mkck5ac82mlqlh0aga',
         'npub182u7auuv6nagxpwnvc28plx7r8czssh4nyzh5488mkck5ac82mlqnpyuwg'),
        ('e5e52edefe2fb8777e0b0f7192da9ebf3dd811a09b189d4407b073f3b7b6d869',
         'nsec1uhjjahh797u8wlstpace9k57hu7asydqnvvf63q8kpel8dakmp5sw3fqnt',
         'npub1uhjjahh797u8wlstpace9k57hu7asydqnvvf63q8kpel8dakmp5sz8zp47'),
        ('b4b4a7dd295fb7831ecd1ecc7fe5ef95478c39811c84740a6b4acb6befa1446b',
         'nsec1kj620hfft7mcx8kdrmx8le00j4rccwvprjz8gzntft9khmapg34sntj903',
         'npub1kj620hfft7mcx8kdrmx8le00j4rccwvprjz8gzntft9khmapg34slaeyfy'),
        ('9783008d1659039eae645704bffc01353571531643572162821f2a9a059522ae',
         'nsec1j7psprgktypeatny2uztllqpx56hz5ckgdtjzc5zru4f5pv4y2hqfve2v7',
         'npub1j7psprgktypeatny2uztllqpx56hz5ckgdtjzc5zru4f5pv4y2hq96jt2t'),
        ('da158d29fc45d8fc622a34807c95a54b20ba2862d7db07c58bec49dc4c1fb68f',
         'nsec1mg2c620ughv0cc32xjq8e9d9fvst52rz6lds03vta3yacnqlk68sqr99lc',
         'npub1mg2c620ughv0cc32xjq8e9d9fvst52rz6lds03vta3yacnqlk68sv4wyed'),
        ('10a5ad1a48540d3a1b87a4379581a9262e7da16d08195ff277d1620fcd5016b5',
         'nsec1zzj66xjg2sxn5xu85smetqdfych8mgtdpqv4lunh693qln2sz66sup6u9l',
         'npub1zzj66xjg2sxn5xu85smetqdfych8mgtdpqv4lunh693qln2sz66ssh3ar2'),
        ('5678473648054df167716c6b5252d98134525bf8006fdb3342bf5ac110a7c988',
         'nsec12euywdjgq4xlzem3d344y5kesy69yklcqphakv6zhadvzy98exyqns7xm8',
         'npub12euywdjgq4xlzem3d344y5kesy69yklcqphakv6zhadvzy98exyqlx48aj'),
        ('7d1d270b6269815c9bb3006af9a5f6d5df94e8cd46526372b56bf69076b82166',
         'nsec105wjwzmzdxq4exanqp40nf0k6h0ef6xdgefxxu44d0mfqa4cy9nq7a56yq',
         'npub105wjwzmzdxq4exanqp40nf0k6h0ef6xdgefxxu44d0mfqa4cy9nqjtlmz4'),
        ('dbba94aae615e0a7b44d6c03b227e8ef07e919f06179a5c986a0a84bc283259f',
         'nsec1mwaff2hxzhs20dzddspmyflgaur7jx0sv9u6tjvx5z5yhs5ryk0s5csd8w',
         'npub1mwaff2hxzhs20dzddspmyflgaur7jx0sv9u6tjvx5z5yhs5ryk0scwmvpm'),
        ('6317c40ab843c230a1f5435a6979dcf7e2afcaeb915438c01eb38be12d6cc6c1',
         'nsec1vvtugz4cg0prpg04gddxj7wu7l32ljhtj92r3sq7kw97zttvcmqs6u6su4',
         'npub1vvtugz4cg0prpg04gddxj7wu7l32ljhtj92r3sq7kw97zttvcmqsk2336q'),
        ('ced2cc757a11e6e6dea49e28ab414b78b0bbc8af2fb1f3575cd01111281963ab',
         'nsec1emfvcat6z8nwdh4ync52ks2t0zcthj9097clx46u6qg3z2qevw4slp4eum',
         'npub1emfvcat6z8nwdh4ync52ks2t0zcthj9097clx46u6qg3z2qevw4snh7c6w'),
        ('94d88722f9fefbba0758b6f626fd6fcc7eb874d212d700fe44c2da9909a6ff40',
         'nsec1jnvgwghelmam5p6ckmmzdlt0e3ltsaxjzttspljyctdfjzdxlaqquxl6fe',
         'npub1jnvgwghelmam5p6ckmmzdlt0e3ltsaxjzttspljyctdfjzdxlaqqss5m0v'),
        ('c5c7c730c2318614d24b0108ca99cd1f5521470efb8d99bb2cab406c30d0a558',
         'nsec1chruwvxzxxrpf5jtqyyv4xwdra2jz3cwlwxenwev4dqxcvxs54vq408aj4',
         'npub1chruwvxzxxrpf5jtqyyv4xwdra2jz3cwlwxenwev4dqxcvxs54vqeevu5q'),
        ('56e86f6bc18c549071cd0909719683aafbaef1599597442231b4f0cfed0fa665',
         'nsec12m5x767p332fquwdpyyhr95r4ta6au2ejkt5gg33kncvlmg05ejsnup0nk',
         'npub12m5x767p332fquwdpyyhr95r4ta6au2ejkt5gg33kncvlmg05ejsl22w4r'),
    ]
    print("\n", file=fd)
    for key, target_nsec, target_npub in nip19_test_vectors:
        print(f' key_bytes = a2b_hex("{key}")', file=fd)
        print(f' assert ngu.codecs.nip19_encode("nsec", key_bytes) == "{target_nsec}"', file=fd)
        print(f' assert ngu.codecs.nip19_encode("npub", key_bytes) == "{target_npub}"', file=fd)
        print(f' assert ngu.codecs.nip19_decode("{target_nsec}") == key_bytes', file=fd)
        print(f' assert ngu.codecs.nip19_decode("{target_npub}") == key_bytes', file=fd)
    print("print('PASS - %s')" % fd.name, file=fd)

    print("run code now in: %s" % fd.name)

print('PASS - test_codecs')
