#include "ft_ssl.h"

// Total length after padding: (len + 1 + padding) % 512 == 512 - size_bytes*8
static int get_padding_len(size_t message_len, size_t size_bytes)
{
    int mod;
    int padding_len;
    int target = 512 - (size_bytes * 8); // 448 pour MD5/SHA (64 bits), 256 pour Whirlpool (256 bits)

    mod = ((message_len * 8) + 8) % 512;
    if (mod < target)
        padding_len = target - mod;
    else
        padding_len = 512 - mod + target;  
    return (padding_len);
}

// Padding + longueur sur size_bytes octets (8 pour MD5/SHA, 32 pour Whirlpool)
char *get_preprocessed_message(char *message, size_t *total_len, bool is_size_big_endian)
{
    int padding_len;
    size_t message_len;
    char *padded_message;

    message_len = ft_strlen(message);
    padding_len = get_padding_len(message_len, 8);
    *total_len = message_len + 1 + (padding_len / 8) + 8;

    padded_message = ft_calloc(*total_len, sizeof(char));
    if (!padded_message)
        return (NULL);

    ft_memcpy(padded_message, message, message_len);
    padded_message[message_len] = 0x80; // padding bit '1'

    // Encoder la longueur en bits sur 8 octets (big-endian ou little-endian)
    uint64_t bit_len = (uint64_t)message_len * 8;
    
    for (size_t i = 0; i < 8; i++) {
        if (is_size_big_endian)
            padded_message[*total_len - 8 + i] = (bit_len >> (8 * (7 - i))) & 0xFF;
        else
            padded_message[*total_len - 8 + i] = (bit_len >> (8 * i)) & 0xFF;
    }

    return (padded_message);
}

char *get_preprocessed_message_whirlpool(char *message, size_t *total_len, bool is_size_big_endian)
{
    int padding_len;
    size_t message_len;
    char *padded_message;

    message_len = ft_strlen(message);
    padding_len = get_padding_len(message_len, 32);
    *total_len = message_len + 1 + (padding_len / 8) + 32;

    padded_message = ft_calloc(*total_len, sizeof(char));
    if (!padded_message)
        return (NULL);

    ft_memcpy(padded_message, message, message_len);
    padded_message[message_len] = 0x80; // padding bit '1'

    // Encoder la longueur en bits sur 32 octets (big-endian ou little-endian)
    uint64_t bit_len = (uint64_t)message_len * 8;
    
    for (size_t i = 0; i < 8; i++) {
        if (is_size_big_endian)
            padded_message[*total_len - 32 + i + 24] = (bit_len >> (8 * (7 - i))) & 0xFF;
        else
            padded_message[*total_len - 32 + i + 24] = (bit_len >> (8 * i)) & 0xFF;
    }

    return (padded_message);
}
