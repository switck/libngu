#ifndef NO_QSTR

/* DEVELOPER NOTE */
/* Since v0.3.0 secp256k1 dropped its generated config header, so the amalgamation
   build below (#include "src/secp256k1.c") never sees the -D defines that
   ./configure would normally pass. The table-size knobs MUST therefore be set
   here, and kept in sync with K1_CONF_FLAGS in the Makefile (used only to
   regenerate the precomputed_ecmult*.c tables via `make precomp`).
   https://github.com/bitcoin-core/secp256k1/blob/master/CHANGELOG.md#removed */

#define COMB_BLOCKS 11
#define COMB_TEETH 6

/* Set window size for ecmult precomputation */
#define ECMULT_WINDOW_SIZE 2

/* Define this symbol to enable the ECDH module */
#define ENABLE_MODULE_ECDH 1

/* Define this symbol to enable the extrakeys module */
#define ENABLE_MODULE_EXTRAKEYS 1

/* Define this symbol to enable the ECDSA pubkey recovery module */
#define ENABLE_MODULE_RECOVERY 1

/* Define this symbol to enable the schnorrsig module */
#define ENABLE_MODULE_SCHNORRSIG 1

/* Define this symbol to enable the musig module */
#define ENABLE_MODULE_MUSIG 1

#define USE_EXTERNAL_DEFAULT_CALLBACKS

# include "src/secp256k1.c"
# include "src/precomputed_ecmult.c"
# include "src/precomputed_ecmult_gen.c"
#endif
