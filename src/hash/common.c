#include "ft_ssl.h"


// Get original message length from the last 8 bytes of the padded message
uint64_t get_message_len(const char *payload, size_t total_len)
{
    uint64_t bit_len = 0;
    for (int i = 0; i < 8; i++)
    {
        bit_len = (bit_len | ((uint64_t)payload[total_len - 8 + i]) << (8 * i));
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

t_hash_params   *process_command_flags(t_ssl_command *command)
{
    t_hash_params *params;

    params = ft_calloc(1, sizeof(t_hash_params));
    if (!params)
        return (NULL);
    params->should_read_stdin = false;
    params->is_quiet = false;
    params->is_reversed = false;

    for (size_t i = 0; i < command->flags_count; i++)
    {
        if (command->flags[i].index == 0)
            params->should_read_stdin = true;
        else if (command->flags[i].index == 1)
            params->is_quiet = true;
        else if (command->flags[i].index == 2)
            params->is_reversed = true;
        else if (command->flags[i].index == 3)
        {
            command->messages[command->message_count].input = ft_strdup(command->flags[i].value);
            if (command->messages[command->message_count].input == NULL)
            {
                return (free(params), NULL);
            }
            command->messages[command->message_count].type = SSL_INPUT_STRING;
            command->message_count += 1;
        }
    }
    return (params);
}