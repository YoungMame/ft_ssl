#include "ft_ssl.h"

uint64_t get_message_len(const char *payload, size_t total_len)
{
    uint64_t bit_len = 0;
    for (int i = 0; i < 8; i++)
    {
        bit_len |= ((uint64_t)(unsigned char)payload[total_len - 8 + i]) << (8 * i);
        printf("bit_len = %" PRIu64 "\n", bit_len);
    }
    return bit_len;
}

char *md5(char *message) {
    char *padded_message;
    size_t total_len;

    padded_message = get_padded_message(message, &total_len);
    uint64_t message_len = get_message_len(padded_message, total_len);
    printf("%" PRIu64 "\n", message_len);
    return (padded_message);
}