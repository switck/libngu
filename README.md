# LibNgU

All the things needed to make Bitcoin work on embedded µpy platforms like ESP32.

Name is "Number Go Up" ... because need that.

**Absoletely none of SHITCOINS allowed here**

## Primative

- using [libsecp256k1](https://github.com/bitcoin-core/secp256k1) for everything, except:
- [mbedtls](https://github.com/ARMmbed/mbedtls) if already present on target (ESP32 uses for TLS)
- otherwise use [cifra](https://github.com/ctz/cifra)
- generic EC, certificates stuff, disabled if no mbedtls
- libwally-core used for testing only

## Notes

- might need, [see issue](https://github.com/micropython/micropython/issues/5224)

    export PKG_CONFIG_PATH=/usr/local/opt/libffi/lib/pkgconfig
    setenv PKG_CONFIG_PATH /usr/local/opt/libffi/lib/pkgconfig

- secp256k1 (see Makefile) has to be configured w/ stuff we need


