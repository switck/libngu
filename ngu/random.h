
#pragma once

// Safe for cryptographic use. Calls must be serialized; Python callers are
// protected by the VM's GIL, while direct C callers own that responsibility.
// Raises a MicroPython exception if the target entropy source fails.
void my_random_bytes(uint8_t *dest, uint32_t count);
