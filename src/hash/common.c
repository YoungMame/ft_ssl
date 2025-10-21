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

int             process_command_inputs(t_ssl_command *command, t_hash_params params)
{
    // If no inputs were provided, read from stdin
    if (command->message_count == 0 || params.should_read_stdin)
    {
        command->messages[command->message_count].type = SSL_INPUT_STDIN;
        command->messages[command->message_count].input = ft_strdup("stdin");
        if (!command->messages[command->message_count].input)
            return (printf("Error: malloc failed\n"), 0); // TODO handle malloc error
        command->message_count += 1;
    }

    for (size_t i = 0; i < command->message_count; i++)
    {
        t_ssl_message   *message = &command->messages[i];

        if (message->type == SSL_INPUT_STDIN)
        {
            // TODO read from stdin
            message->content = read_fd(STDIN_FILENO);
            if (!message->content)
                return (0); // TODO handle read error
        }
        else if (message->type == SSL_INPUT_FILE)
        {
            int fd = open(message->input, O_RDONLY);
            if (fd < 0)
            {
                ft_printf("ft_ssl: %s: No such file or directory\n", message->input);
                return (0); // TODO handle open error
            }
            message->content = read_fd(fd);
            close(fd);
            if (!message->content)
                return (0); // TODO handle read error
        }
        else if (message->type == SSL_INPUT_STRING)
        {
            printf("type string detected\n");
            message->content = ft_strdup(message->input);
            if (!message->content)
                return (0); // TODO handle malloc error
        }
    }
    return (1);
}

t_hash_params   process_command_flags(t_ssl_command *command)
{
    t_hash_params params;

    params.should_read_stdin = false;
    params.is_quiet = false;
    params.is_reversed = false;

    for (int i = 0; i < command->flag_count; i++)
    {
        if (command->flags[i].index == 0)
            params.should_read_stdin = true;
        else if (command->flags[i].index == 1)
            params.is_quiet = true;
        else if (command->flags[i].index == 2)
            params.is_reversed = true;
        else if (command->flags[i].index == 3)
        {
            command->messages[command->message_count].input = ft_strdup(command->flags[i].value);
            command->messages[command->message_count].type = SSL_INPUT_STRING;
            command->message_count += 1;
        }
    }
    return (params);
}

void    output_messages(t_ssl_command *command, t_hash_params params, const char *algo_name)
{
    for (size_t i = 0; i < command->message_count; i++)
    {
        t_ssl_message   *message = &command->messages[i];

        if (params.is_quiet)
        {
            printf("%s\n", message->output);
        }
        else if (params.is_reversed)
        {
            if (message->type == SSL_INPUT_STRING)
                printf("%s %s\n", message->output, message->input);
            else if (message->type == SSL_INPUT_FILE)
                printf("%s %s\n", message->output, message->input);
            else
            {
                if (params.should_read_stdin)
                    printf("%s(%s)= %s\n", algo_name, message->content,message->output);
                else
                    printf("%s(%s)= %s\n", algo_name, message->input, message->output);
            }
        }
        else
        {
            if (message->type == SSL_INPUT_STRING)
                printf("%s(%s)= %s\n", algo_name, message->input, message->output);
            else if (message->type == SSL_INPUT_FILE)
                printf("%s(%s)= %s\n", algo_name, message->input, message->output);
            else
            {
                if (params.should_read_stdin)
                    printf("%s(%s)= %s\n", algo_name, message->content,message->output);
                else
                    printf("%s(%s)= %s\n", algo_name, message->input, message->output);
            }
        }
    }
}