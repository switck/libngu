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

/* Window for the general ecmult table (secp256k1_pre_g). Governs the BIP-32 *public*
   key derivation hot path (pubkey_tweak_add) as well as ECDSA/Schnorr verify and MuSig.
   8 == ~29% faster public derivation than 2, for +8KB flash */
#define ECMULT_WINDOW_SIZE 8

/* NGU_INCL_SCHNORR / NGU_INCL_MUSIG are set by the build (ngu/micropython.mk),
   default off; they gate the optional schnorrsig / musig modules below. */

/* Always built: cheap, and the keypair/xonly types are broadly useful. */
/* Define this symbol to enable the ECDH module */
#define ENABLE_MODULE_ECDH 1

/* Define this symbol to enable the extrakeys module */
#define ENABLE_MODULE_EXTRAKEYS 1

/* Define this symbol to enable the ECDSA pubkey recovery module */
#define ENABLE_MODULE_RECOVERY 1

/* Optional: BIP340 Schnorr (and, transitively, MuSig2). */
/* Define this symbol to enable the schnorrsig module */
#if NGU_INCL_SCHNORR
#define ENABLE_MODULE_SCHNORRSIG 1
#endif

/* Define this symbol to enable the musig module */
#if NGU_INCL_MUSIG
#define ENABLE_MODULE_MUSIG 1
#endif

#define USE_EXTERNAL_DEFAULT_CALLBACKS

# include "src/secp256k1.c"
# include "src/precomputed_ecmult.c"
# include "src/precomputed_ecmult_gen.c"
#endif
