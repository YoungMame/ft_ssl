#include "ft_ssl.h"

// Total length after padding need to be len + 1 % 512 == 448
int get_padding_len(size_t message_len)
{
    int mod;
    int padding_len;

    mod = ((message_len * 8) + 8) % 512;
    if (mod < 448)
        padding_len = 448 - mod;
    else
        padding_len = 512 - mod + 448;  
    return (padding_len);
}

// Padding the message with a single 1 bit followed by 0 bits until the padded length is reached
// and appending the original message length as a 64-bit big-endian integer
char *get_preprocessed_message(char *message, size_t *total_len, bool is_size_big_endian)
{
    int padding_len;
    size_t message_len;
    char *padded_message;

    message_len = ft_strlen(message);
    padding_len = get_padding_len(message_len);
    *total_len = message_len + 1 + (padding_len / 8) + 8;

    // DEBUG
    // ft_printf("message_len = %" PRIu64 "\n", message_len);
    // ft_printf("padding_len = %i\n", padding_len);
    // ft_printf("total_len = %li\n", *total_len);

    padded_message = ft_calloc(*total_len, sizeof(char));
    if (!padded_message)
        return (NULL);

    ft_memcpy(padded_message, message, message_len);
    padded_message[message_len] = 0x80; // bit de padding '1'

    uint64_t bit_len = (uint64_t)message_len * 8;
    for (int i = 0; i < 8; i++) {
        if (is_size_big_endian)
            padded_message[*total_len - 8 + i] = (bit_len >> (8 * (7 - i))) & 0xFF;
        else
            padded_message[*total_len - 8 + i] = (bit_len >> (8 * i)) & 0xFF;
    }

    return (padded_message);
}
