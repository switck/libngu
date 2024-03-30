#pragma once

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"
#include "secp256k1/include/secp256k1_extrakeys.h"
#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1_schnorrsig.h"
#include "secp256k1/include/secp256k1_preallocated.h"


// Shared context for all files in ngu. Never freed.
// - big heavy shared object for all calls

// shouldn't this be randomized again at least for signing?
extern secp256k1_context   *lib_ctx;

// Call anytime, does nothing if already setup
extern void sec_setup_ctx(void);

