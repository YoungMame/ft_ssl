#include "ft_ssl.h"

uint32_t    left_rotate(uint32_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

uint32_t    right_rotate(uint32_t value, int shift)
{
    return (value >> shift) | (value << (32 - shift));
}

uint8_t    mem_xor_8(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t result = 0;
    for (size_t i = 0; i < len / sizeof(uint8_t); i++)
    {
        result ^= (a[i] ^ b[i]);
    }
    return result;
}

uint32_t    mem_xor_32(const uint32_t *a, const uint32_t *b, size_t len)
{
    uint32_t result = 0;
    for (size_t i = 0; i < len / sizeof(uint32_t); i++)
    {
        result ^= (a[i] ^ b[i]);
    }
    return result;
}