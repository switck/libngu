
#pragma once

// Safe for crypto purposes. Not thread-safe: calls must be serialized --
// the VM's GIL does this for Python callers; direct C callers outside the
// VM own that themselves. Raises (mp exception) if the entropy source fails.
void my_random_bytes(uint8_t *dest, uint32_t count);

