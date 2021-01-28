#pragma once

// bitcoin-specific ops
void hash160(const uint8_t *msg, int msglen, uint8_t digest[20]);

void sha256_single(const uint8_t *msg, int msglen, uint8_t digest[32]);

void sha256_double(const uint8_t *msg, int msglen, uint8_t digest[32]);

typedef union {
    struct {
        uint8_t     left[32];
        uint8_t     right[32];
    } lr;
    uint8_t     both[64];
} left_right_t;

void hmac_sha512(const uint8_t *key, uint32_t key_len,
                    const uint8_t *data, uint32_t data_len,
                    left_right_t *result);

