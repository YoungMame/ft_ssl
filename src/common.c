#include "ft_ssl.h"

// Retrieve original message length from the last 8 bytes of the padded message
uint64_t get_message_len(const char *payload, size_t total_len)
{
    uint64_t bit_len = 0;
    for (int i = 0; i < 8; i++)
    {
        bit_len = (bit_len | ((uint64_t)(unsigned char)payload[total_len - 8 + i]) << (8 * i));
    }
    return bit_len;
}

void    free_chunk(uint32_t **M, size_t chunk_count)
{
    for (size_t i = 0; i < chunk_count; i++)
    {
        free(M[i]);
    }
    free(M);
}

// Allocate the good number of chunks and the words in it
uint32_t **allocate_chunk(size_t chunk_count)
{
    uint32_t **M = ft_calloc(chunk_count, sizeof(uint32_t*));
    if (!M)
        return (NULL);

    for (size_t i = 0; i < chunk_count; i++)
    {
        M[i] = ft_calloc(16, sizeof(uint32_t));
        if (!M[i])
        {
            for (size_t j = 0; j < i; j++)
                free(M[j]);
            free(M);
            return (NULL);
        }
    }
    return (M);
}

uint32_t    left_rotate(uint32_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

uint32_t    right_rotate(uint32_t value, int shift)
{
    return (value >> shift) | (value << (32 - shift));
}