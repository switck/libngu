// Test double for the "gates" target only (see Makefile): just enough of
// ESP-IDF for a host syntax-compile of ../random.c's ESP32 branch, so the
// valid-attestation case must actually succeed. Never part of any build.
#pragma once
#include <stdint.h>

uint32_t esp_random(void);
