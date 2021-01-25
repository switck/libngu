import gc, ngu  # auto-gen
HDNode = ngu.hdnode.HDNode
for i in range(3):
  a = HDNode(); a.from_master(b'\x8a\x83f_7\x98r\x7f\x14\xf9*\xd0\xe6\xc9\x9f\xda\xb0\x8e\xe71\xd6\xcddL\x13\x12#\xfd/O\xed*')
  assert a.pubkey() == bytearray(b"\x02\xa1\xce\x93\xdf\xe9f\x7f\x12\x0f\xda4/Z\'sE\xa2b\'\x8c\x1e w\x04\nZ\xc0\r\x05\x8am]")
  assert a.privkey() == bytearray(b'uU\x864\xdc\xb8ys2&\xee\xf10\xd6\xcf\x04+\x0c\x1e@\x16\xb4\xd0W\xbe\xfc\xfd\xdc\xa5]_\xcf')
  assert a.my_fp() == 0x3e5730c5
  assert a.chain_code() == b'\x17\x02\x86iJ\x9d\xc3\xa1\xd1\xc1\xe8\x0ex\xf79I2\xfa\x00\x18\x96\xeb\xb85\xc6o.\x9eF\xa3"f'
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K2HeKSGTsSD7CsAeCKLo79drPawSr5UwNbkJtNCPQctJmGyGT6rqHgiwGLdGwZEj9ke74BG43pSvLBDNXSffNi4dnvDQtEqs'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcEminYHzsoM3wRCUgioWxWrmzPKrTdpUMUYe2ujhfAgdF8EdoYUgE1HYLMtcUMuwzejGcXcry3LCrXmuffCCRyHvDM42rbPf'
  assert a.addr_help(0) == '16gdLzq66oSF7pKNo5eoKCyPaYYWsF6nmK'
  
  a = HDNode(); a.from_master(b'\x16?\xdcN\xaa\x02\xc5k~\x9d\xcf\xf4< \xa3\xdah\xdd\xbb&\xffjI\x8d\xd0P:\xe4\x843\xd4\xe9')
  assert a.pubkey() == bytearray(b'\x02\xa5\x02s\x91/TZ5<\xec\x9d\xbd\x18\xd1l\xb4\x8f\x08\xa5\x0f\x0b\xf9\xbe\xaf(\x81\xfc\xea\x1d\x1c\xde\xfd')
  assert a.privkey() == bytearray(b'\x11ly\xae\xa7\xc2\xda\xe6\x1e\x96h\xa7MU\xbb\x10\xb3\x89,e\x19\xf5\xa8\xa7\xfd\x887{>B\x1f\xad')
  assert a.my_fp() == 0xb8a4bcff
  assert a.chain_code() == b'\x1e\xe1=0\x98\xf6\x0c\x08\xf2x\xfe{\\\xbd\xa2\x08q\xfffA"\x99T<BH2Js\x0c#V'
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K2NBuBx2zSHpihPxBZR4DJKrr3YteF4AbJH18xRStLJvu1eTwX1H8Dj6PhvgwEJq5HXDgn4EyS9jVwREPWfpVDQ1LLQvpGWP'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcErGNHyZzoRmTFRnfxsn4fYnSqwJFoPhaB5LHVxm8t7FNrvchqpQoBy5oSJ4Jm396AcLYqoR7N6iEcTGHtLndFGbLzJ2FB9Y'
  assert a.addr_help(0) == '1HqJgWmXQ5aNJ3rFktFcL8Rq92UAwFC3BK'
  
  a = HDNode(); a.from_master(b'\xc6A\x8a\xbd\x9f\xcc\xfb`H\xf1\xd0/\x9f-?\x15\x83\xbb\xc8<>\x08\xa4\xadtXo\x01Y\xdc\xda9')
  assert a.pubkey() == bytearray(b'\x02\x17G\xc6\xe1\x15\x13E\x8en\xb6\\*\xbb\xc4b\xd6\xf6\xf3C\xd3$p\x826\xfdc\x14\xfe\xc2\xfcj\xd8')
  assert a.privkey() == bytearray(b'\xdf$\x18\xfek\x1f2\xc7\xd1/A\xddS\xe9\x9fW\xafZP\xad\x0f\x10\x95\xf4\xf2\xce+\t\xcf\xd8m*')
  assert a.my_fp() == 0x0e20ad95
  assert a.chain_code() == b'\x08O"\x02\xbcL\xd8\xac\x9b\xf5\xcb;\x91\xfdF\xbdm3\xcd/\xfb\xf5 wd\x87^|\tB\x8a('
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K299xd6oF1yFX7xeGYX88dZgaNFft3QexbGBRUqDj3Nkr2BURAAHkQTD5Z2M6QbJ1Rb8Hn5Yiw1QDdo2Dr3XzrgQHHc9jAkh'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcEdERj8LFP7CFfzUkwyqyzncBAe5VbkBwU4Wa2NXybB5KsQzARrQfr8FW79AUHQTgvbwQhJJMqXAJoT2SZJ66w49GndkvDJE'
  assert a.addr_help(0) == '12HhcCR77NSEp4J29WsRPzoiah9rysD1rs'
  
  a = HDNode(); a.from_master(b"\x90\xdb\x87\x0ba\xc2D'^\xc3\x7f\x10\x82\xb0\xa0s\xb8\x96\xdf\x1a\xc2*J\n(d\x0e#\xd3\xa6Z\xc5")
  assert a.pubkey() == bytearray(b'\x03\xb1\xb2\x98\xe8J\xb3)\xa1\xe9\x9bm\x1e\xbb\xe5\xfd\xe3\x8b@\x8f\xe5\xcd8_\xeb\x87a\xb1)s\xdaF{')
  assert a.privkey() == bytearray(b'p\xdae\xaa>\x95&N\xe5\x90<\xf2\xe7}\xcf=^\xfe\xa7\x95h;\\\x1f:\xcf\xdb\xb3^\n\xb6\x84')
  assert a.my_fp() == 0xf40e24a3
  assert a.chain_code() == b'k\xfd\xa0\xaf\x06\xe5\x03\xc8\\\xc37t\xf0]\xa7\xb7\x91\x80r\xb3\x03\xd1\x1b\x8e;\x1dh;I/+T'
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K38iWGktQCx6MtA62TfyWGu3VyQzfvS9PPenegC5TTqj3yRoac3Vqe4SVuWWvs5mW7PySKMM9tpPEUa96D3q93sizA4FhjD1'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcFcnyNnRQa636SBvWs8hMe7y6moQHUmgNGT7oDjPi1e3XpjGebB2F46zXMbTL5MRH1d9i3vsnUKhiNZh211ge8XQatnpxayX'
  assert a.addr_help(0) == '1PFSpVH1hsnegFVMSBYY7A1GsQEktWBw1U'
  
  a = HDNode(); a.from_master(b'\xc3\xe4Gl\xeb\xfc\xc7\x00`\xa0!;\xa5\x13\xf0!i\x17F\xf2%#^q\xb2\xe6\xf6\xf9\xe1\xf5\x9c\xf5')
  assert a.pubkey() == bytearray(b'\x03\xd1\xfc\xc2G\xd1\xc2u&\x81o\x1f\xcf\x9cXj&TJ\x9bS\x8c]\xaa(\xd2\xd5\xd7\x91\xfe\xaf\x99\xbf')
  assert a.privkey() == bytearray(b'6L\x1c]\x89\xe0\xe7\xd2\xc0I\x99\x04wl\xf6`\x82M\xecgw%\x1f\x8b\x15\xe1,E\x1b\xe6\xb3\xdc')
  assert a.my_fp() == 0x6535a0f5
  assert a.chain_code() == b"\xb4\xb8\xdb\xbc\xb5x%\xb0\xbd}\x9f\x06\xbe\xd9'\x90\xed\xbb\x88\x15`U\x0e!\xa1EX\xde`\xc3\x0b\xee"
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K3riRx7opRYHuAdnAu5x4CChd1K51SLXkUeaXC6tB4Lt9ddjVSvvSBiFqPdhojuuZSZLrLxJkwjgXMnMhcq3nbkjpU3iWwTM'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcGLnu49LpngEdifcfJYfuZRdDohUczg4jMSufjeCRc9CdUwtZxb8mriEHjV1ST1wWj9uA1oeEmZe6chWirNqU7orLGzHMAmn'
  assert a.addr_help(0) == '1AE9VZpgjmQWNdBJ89CQrHgGHQbQkP1cHh'
  
  a = HDNode(); a.from_master(b'Z\xbf\xbc\nei@]\t+\x82\x9ad\x0cRs\xb0VB\x95^\xb0\xe4\xb5\x18\xb4\x11\xd12\xa1\xb04')
  assert a.pubkey() == bytearray(b"\x02n\xcd\xd1\xa8\xd4\xe5\x06\n\'J5\x95W\xbd!\xf5\xa6\x01\xc4A\xbb\x85\xadT\x98\x18\xd5\xb5$\xf0\xb8v")
  assert a.privkey() == bytearray(b'\x92\xff\xb2\x8c\x1d\x15\xc1t3sB}eJ\xec\x7f\xfb\xd3\xac7"e\xc2\xfe\xbc\xbf*$\x00\xd2\xd9p')
  assert a.my_fp() == 0xf0a9f581
  assert a.chain_code() == b'/\x93 \xad\x14\x90\xd3\xcbV\xcfb\x9dZ\xf1\xe6\xcd,f\xc2\xb5\xa1;\xc8Sf2b\x8e>\xca\xed\xc4'
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K2Xq3gA4heLtDwo1qJiboMe1sr2Pe9hLxwzH1V6va5YEaxMTmfVjFaPxqXZwxZow81jfBWeosYToQYfH8PapoaDfNcg8uKgD'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcF1uWnBbi1UpxVprKiBKeirwUeQoFi2swpncA2eEpdLZ4ocDbZKSor3WLSLr4Cuwn2FYJxbtr37RB5MdkH6A8gQMaFqPMYYA'
  assert a.addr_help(0) == '1NwWmzv4agWdSBW2ioJqjJAc6BRtfhNm41'
  
  a = HDNode(); a.from_master(b'\x81\xecpG@\x1e\x8f\xbcL\xfb\x7f\xb2\xc4\xb0h\xd3\xc8\xd7h\xbc\xd4\xe0t\xfa*\xfeA\xd9\xb8\x05\x18\xbd')
  assert a.pubkey() == bytearray(b'\x03\xb9T\x91\x1a\xef\xde>\xe9\xde3D\xd3\x9eC\x0c\x93\xff\xcd}$\x08<\xaf\xa8\xf9m\xe1\x1dgP!@')
  assert a.privkey() == bytearray(b'(\x14\xd6\x87\xfb\xd0\xd0\xe9\xb7\xfa\x8b\xe8+\x06\xc1\xd4|\n\xfc\xd8\x8f\xc2f\x95Dg\xceN\x1dI:1')
  assert a.my_fp() == 0xe1c4ee68
  assert a.chain_code() == b'1\xdf\xf1_\xd6\xd1_\xca\xa3\xfd\x80#\x97\xa7\x91?\xdaP\xa1i\xe4\x1c\xe8\xfeOfE\x8e?g\xeb\xfc'
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K2ZA5dr8t91BpN2YeNwhGZGVzZC4vqDWZ3ut5jviQFDnkmJVXaFHNwcrtxr9XG6MBkiqAUqjVrP6UTDzR5B4SpGsaGszusmi'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcF3EYjsftW98Yv4P8nQR7vVRbMaUYPZ3XviDEHU2eo27Ecca1P6PrTLwi8osvK1YQP85VpgdGCX95fxHmsGBn13AJhqPQT1S'
  assert a.addr_help(0) == '1MakxBrJ9Q2FnGKWfp9NwTDqE6KGvdPXfA'
  
  a = HDNode(); a.from_master(b'\xfaI\xc7\x84\rc\xc7\xd3&\xba>G\xff\x04*\x18\xae7\x8da\x9cf\x83\x9f\x97\x93\xb2\xce\xf2A\xcd\xcf')
  assert a.pubkey() == bytearray(b'\x03oW\x95s\x04\xa1\xdd\x97\x15\rhR\x9e\x9e\xa8\xf0\xc3\x91e\xb3[\xbb\xb9q\xd3\x03Q\xb1\xe6\xdc\xc1\x1d')
  assert a.privkey() == bytearray(b'I&\xbe\xdcsd\xec\xca\xf7\xf0-\xa4H\xe0\xcb\x11\xffP\xe8\x1c\x9ePE=\x1f\x95\x85u,\xef&i')
  assert a.my_fp() == 0x5dc3d644
  assert a.chain_code() == b'\x07p/\xa8\x83\xe0Y|\xed\xd3E\xb3H\xc5Y\xd2s?\xd0\xf1\xe9\x19\x0e>\x1eW\x8d \x97\xd1\xfa\x1c'
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K28enthxXK7a7UaqfbUmv42rXYYQJ1Md1xdTTTRbtp2bWorA3vEiKbLNdqvNBaaS5mNg3H6smRBbTc7mrjJD3PL1UoLT1Pt3'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcEcjFzjVXgFWr2cg9zwVmRFn8LvouZh9zqRnbzxv9Mpuzf9RP4y6vpsMCBNGZjP9zrLCKPbPDZSo3UkfGg2igpN7ivJtvHbc'
  assert a.addr_help(0) == '19YnSqJa7R5BedziD6PdMzZYdiF7L8akVo'
  
  a = HDNode(); a.from_master(b'\xb6\x80\x82@x\xf9\x13Ryr\nY{@\xc2\xf5\x01\xf4\xf5\x08\xa6\xec\x05a\x8c\x9b\xa5\x03~\xccC^')
  assert a.pubkey() == bytearray(b'\x03\xa5\xb8\x8e\xac>\xc2\x00`\x91\x91\x87x\x81\xb6p\x0c)\xb2\xfbD\x0f!\xa3\x11\x82\xa1\x8d\x81$\x9ch\x1b')
  assert a.privkey() == bytearray(b'\xb4\x02\xbf\xa54z\xe3\xf2~|\xfa\xf3\xcc\xe6U\x04\xc7\xccB\xf1=\xdba\xe2\xaaM\xc0L\xd9\xbb\xb9\xaa')
  assert a.my_fp() == 0xa1137a3b
  assert a.chain_code() == b'\xd2\xcf\xcbQ1Nc\xa3w\xceh\xe6\x8a\xfe\xe2\xf7\xbb\x85N$\x0c\xf5\x17\x1c\x9d\x9e\\\\\xc0\x99\x02\xfd'
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K4A6CDwt2WnkHCveBEhPaRSQ43VAU7pRTgujYwoiPGgitvyLRjuxygAft45uS44uh7Yuw4s3dgtSMDFsWBAnF6HgQRjV7BTW'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcGeAfKyR2svh1kxUfeA7RnfKeqsa5g9xSZi4hVM2dpV3NnGCeLyKsmpjypxgVXemPvMyurTzkx1ZUumjcRFuksgLYm27p67t'
  assert a.addr_help(0) == '1Fgh8CmfY9qvxFQDTGfY3DeLUV9ZTnybZ9'
  
  a = HDNode(); a.from_master(b'\\\x9bC\x8a$4H4@O\xe8\xca\x8d\xe2\xd9\xc7\xe5\xfa\x86G6\xe3M\x7f\x8c\xaaa\xde_\xc4\xdb\x07')
  assert a.pubkey() == bytearray(b"\x02t\x9d|\xe9:\x8aq\xbb\xe9\xbd\xbf\x1eM=\'\x1b\x14\xb9\xbe\x7fcRQ0\xa1\xf2tU\xca`\x7fA")
  assert a.privkey() == bytearray(b'\xd4\x8c]+B\xf9\xc4\xdbz>l\xed5z.f\xd7\x00\xda\xf6\x14\x16_;\x7f\xecL#\x8d\xcc\x14?')
  assert a.my_fp() == 0xcb698e19
  assert a.chain_code() == b'\x8cc`\x0f\xbcz\x18\x92\xbe\xc6\xe6\xa7\xce\x95y\xbbA\x1c\x9d\xeeE\x1c\xbe\x91\xfc?\x12\xf9\x9b\x15x\xcb'
  assert a.serialize(0x488ade4, 1) == 'xprv9s21ZrQH143K3TRZeweaf2JK3wM22bBGmfhZ8TEQLKypfDSNqptATDGvH3ghbYyaUmnunRQSs8P9dpED9M85rc6u2zhLPBnskHrWtyeY2KX'
  assert a.serialize(0x488b21e, 0) == 'xpub661MyMwAqRbcFwW2kyBb2AF3byBWS3u88td9vqe1tfWoY1mXPNCR11bQ8HzDZCp2v8wUKaMRCuM2hLU1iToEE2xAymg69kFzivaJAKRnKgc'
  assert a.addr_help(0) == '1KYYd3AUg8jAi2tXrqKDAF61z4Htv2bX4g'
  
gc.collect()
print('PASS')
