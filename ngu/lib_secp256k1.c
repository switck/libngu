#ifndef NO_QSTR

/* DEVELOPER NOTE */
/* This MUST match what is passed to configure in Makefile via K1_CONF_FLAGS */
/* This is a reaction to v0.3.0 and removal of configuration header */
/* https://github.com/bitcoin-core/secp256k1/blob/master/CHANGELOG.md#removed */

/* Set ecmult gen precision bits */
#define ECMULT_GEN_KB 2

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

#define USE_EXTERNAL_DEFAULT_CALLBACKS

# include "src/secp256k1.c"
# include "src/precomputed_ecmult.c"
# include "src/precomputed_ecmult_gen.c"
#endif
