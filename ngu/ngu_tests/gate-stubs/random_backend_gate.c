#include "random_backend.h"

void random_backend_gate(void)
{
    uint32_t word;
    (void)chip_trng_read(&word);
}
