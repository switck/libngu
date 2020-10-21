# LibNgU

All the things needed to make Bitcoin work on embedded µpy platforms like ESP32.

Name is "Number Go Up" ... because need that.

**Absoletely none of SHITCOINS allowed here**

## Notes

- might need, [see issue](https://github.com/micropython/micropython/issues/5224)

    export PKG_CONFIG_PATH=/usr/local/opt/libffi/lib/pkgconfig
    setenv PKG_CONFIG_PATH /usr/local/opt/libffi/lib/pkgconfig

- secp256k1 (see Makefile)

    ./configure --enable-module-recovery --with-bignum=no

