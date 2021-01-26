#pragma once

#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_recovery.h"
#include "secp256k1/include/secp256k1_extrakeys.h"
#include "secp256k1/include/secp256k1_ecdh.h"


// Shared context for all files in ngu. Never freed.
// - big heavy shared object for all calls
extern secp256k1_context   *lib_ctx;

// Call anytime, does nothing if already setup
extern void sec_setup_ctx(void);

