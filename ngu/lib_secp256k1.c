#ifndef NO_QSTR

# define USE_EXTERNAL_DEFAULT_CALLBACKS

# include "src/secp256k1.c"
# include "src/modules/extrakeys/main_impl.h"
# include "src/modules/schnorrsig/main_impl.h"
# include "src/modules/recovery/main_impl.h"
# include "src/modules/ecdh/main_impl.h"
# include "src/precomputed_ecmult.c"
# include "src/precomputed_ecmult_gen.c"
#endif
