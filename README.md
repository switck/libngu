# LibNgU

All the things needed to make Bitcoin work on embedded µpy platforms like ESP32.

Name is "Number Go Up" ... because need that.

**Absoletely none of SHITCOINS allowed here**

**NEW POLICY** If I don't know you, I don't merge you! Thanks **XZ**!

## Primitives

- using [libsecp256k1](https://github.com/bitcoin-core/secp256k1) for everything, except:
- [mbedtls](https://github.com/ARMmbed/mbedtls) if already present on target (ESP32 uses for TLS)
- otherwise use [cifra](https://github.com/ctz/cifra)
- generic EC, certificates stuff, disabled if no mbedtls
- AES submodule disabled if you have mbedtls, because ucryptolib is same
- libwally-core used for testing only

## Notes

- might need, [see issue](https://github.com/micropython/micropython/issues/5224)

    export PKG_CONFIG_PATH=/usr/local/opt/libffi/lib/pkgconfig
    setenv PKG_CONFIG_PATH /usr/local/opt/libffi/lib/pkgconfig

## Install

- `make one-time` does submodule bullshit, configures K1 lib
- `make quick` compiles Unix micropython port, runs tests
- can play with `./ngu-micropython` binary on your desktop
- ESP32 is intentionally unavailable for now: the build stops until someone
  validates the target's entropy lifecycle and hardware-SHA behavior and
  attests (see "Random numbers: integrator obligations" below). Once that
  exists:
```
make -f makefile.esp32
make -f makefile.esp32 deploy
```
- on target, do:
```
>>> import ngu_tests.run
```
or for single test:
```
>>> import ngu_tests.test_hash
```

- STM32 port builds, but untested:
```
make -f makefile.stm32 
```



## Random numbers: integrator obligations

All output of `ngu.random` (and every private key this library generates)
comes from the NIST SP 800-90A §10.1.2 HMAC_DRBG core (SHA-256; reseed
interval and prediction resistance deliberately omitted, see `hmac_drbg.c`)
seeded from your target's entropy source, with fresh entropy words XORed
over every output. The construction is verified against official NIST CAVP
vectors (`ngu_tests: make cavp`), and the compile-time gates below are
regression-tested (`ngu_tests: make gates`). None of that helps if the
entropy source itself is not real, so, per target:

- **STM32**: you must compile with `-DNGU_STM32_RNG_GET_IS_HARDWARE=1`, which
  is your attestation that the `rng_get()` symbol that gets *linked* reads the
  MCU's TRNG peripheral. This cannot be checked by the preprocessor: when a
  board sets `MICROPY_HW_ENABLE_RNG` to 0, upstream MicroPython silently
  provides a pseudo-random `rng_get()` (Yasmarang seeded from device UID and
  clocks) in its place. Strongly recommended: enforce your attestation at
  link time — assert with `nm` that upstream's `rng.o` defines no symbols and
  that your board's `rng.o` exports `rng_get` (see `rng-code-check` in the
  Coldcard firmware's `stm32/shared.mk` for the pattern).
- **ESP32**: `esp_random()` is used, and you must compile with
  `-DNGU_ESP32_RNG_IS_TRUE_RANDOM=1` — your attestation that a true entropy
  source (RF, or the bootloader's) is active before the first RNG call on
  your chip and boot sequence; otherwise `esp_random()` is pseudo-random.
  Note ESP-IDF also enables hardware SHA (`MBEDTLS_SHA256_ALT`) by default,
  which this DRBG refuses at compile time until its no-fail contract is
  proven for the target.
- **Unix**: the OS CSPRNG is used (`arc4random()` on macOS/FreeBSD,
  `getentropy()` on Linux). Nothing to do. Other unixes fail the build
  until someone adds and tests their entropy call.
- Any other target fails the build on purpose. There is no software fallback.

Additionally:

- An entropy source whose next word matches either of the previous two
  accepted words raises `OSError` (unclocked TRNG, oscillating source);
  the history persists across calls. On STM32, a zero word is refused
  outright, since upstream `rng_get()` also returns 0 on timeout.
- Feed `ngu.random.reseed()` any extra entropy you have (secure elements,
  dice rolls). It accepts bytes of any length and *mixes* into the DRBG
  state, so sources compose and a bad one cannot displace a good one.
  The legacy `reseed(int)` form still works but carries at most 32 bits.
- Before shipping hardware, validate the raw TRNG output statistically
  (dieharder/PractRand over ≥ 1 GB), not just the DRBG output.
- `ngu.random` keeps unsynchronized state, and refuses to build with
  threads enabled but the GIL off. With the GIL (or no threads) the VM
  serializes calls; direct C callers outside the VM own that themselves.
