#include "ft_ssl.h"

uint32_t    left_rotate(uint32_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

uint32_t    right_rotate(uint32_t value, int shift)
{
    return (value >> shift) | (value << (32 - shift));
}