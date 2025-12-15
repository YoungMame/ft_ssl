# include "ft_ssl.h"

// static void pbin(uint64_t v)
// {
//     uint64_t mask = (uint64_t)1 << 63;
//     while (mask) {
//         printf("%d", (v & mask) ? 1 : 0);
//         mask >>= 1;
//     }
//     printf("\n");
// }

// static void pbin8(uint8_t v)
// {
//     uint8_t mask = (uint8_t)1 << 7;
//     while (mask) {
//         printf("%d", (v & mask) ? 1 : 0);
//         mask >>= 1;
//     }
//     printf("\n");
// }

static void check_hex_len(char *str, size_t expected_len)
{
    size_t len = ft_strlen(str);
    if (len > expected_len)
    {
        ft_printf("ft_ssl: hex string is too long, ignoring excess\n");
        str[expected_len] = '\0';
    }
    else if (len < expected_len)
    {
        ft_printf("ft_ssl: hex string is too short, padding with zeros bytes to length\n");
        char *padded = ft_calloc(expected_len + 1, sizeof(char));
        if (!padded)
            return (ft_printf("ft_ssl: Error: Memory error\n"), (void)0);

        size_t diff = expected_len - len;
        for (size_t i = 0; i < diff; i++)
            padded[i] = '0';
        for (size_t i = 0; i < len; i++)
            padded[diff + i] = str[i];
        for (size_t i = 0; i < expected_len + 1; i++)
            str[i] = padded[i];
        free(padded);
    }
}

int             base64_process_command_inputs(t_ssl_command *command)
{
    if (command->message_count == 0)
    {

        command->messages[command->message_count].input = ft_strdup("stdin");
        command->messages[command->message_count].type = SSL_INPUT_STDIN;
        command->messages[command->message_count].content = read_fd(STDIN_FILENO, &command->messages[command->message_count].content_size);
        command->message_count += 1;
        if (!command->messages[0].content)
            return (ft_printf("ft_ssl: Error: cannot read\n"), 0);
    }
    else
    {
        int fd = open(command->messages[0].input, O_RDONLY);
        if (fd < 0)
            return (ft_printf("ft_ssl: %s: No such file or directory\n", command->messages[0].input), 0);
        command->messages[0].content = read_fd(fd, &command->messages[0].content_size);
        close(fd);
        if (!command->messages[0].content)
            return (ft_printf("ft_ssl: Error: cannot read\n"), 0);
    }
    return (1);
}

t_base64_params   base64_process_command_flags(t_ssl_command *command)
{
    t_base64_params params;

    params.decode = false;
    params.output_fd = STDOUT_FILENO;

    for (int i = 0; i < command->flag_count; i++)
    {
        if (command->flags[i].index == 0)
            params.decode = true;
        else if (command->flags[i].index == 1)
            params.decode = false;
        else if (command->flags[i].index == 2 && command->flags[i].value && command->message_count == 0)
        {
            command->messages[command->message_count].input = ft_strdup(command->flags[i].value);
            command->messages[command->message_count].type = SSL_INPUT_FILE;
            command->message_count += 1;
        }
        else if (command->flags[i].index == 3)
        {
            params.output_fd = open(command->flags[i].value, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (params.output_fd < 0)
                return (ft_printf("ft_ssl: Error: %s: Cannot open output file\n", command->flags[i].value), params);
        }
    }
    return (params);
}

void    base64_output_messages(t_ssl_command *command, t_base64_params params, const char *algo_name)
{
    (void)algo_name;
    for (size_t i = 0; i < command->message_count; i++)
    {
        t_ssl_message   *message = &command->messages[i];

        ft_putstr_fd(message->output, params.output_fd);
        ft_putstr_fd("\n", params.output_fd);
    }
    return ;
}

int             des_process_command_inputs(t_ssl_command *command, t_des_params params)
{
    if (command->message_count == 0)
    {
        command->messages[command->message_count].input = ft_strdup("stdin");
        if (!command->messages[command->message_count].input)
            return (ft_printf("ft_ssl: Error: memory error\n"), 0);
        command->messages[command->message_count].type = SSL_INPUT_STDIN;
        command->messages[command->message_count].content = read_fd(STDIN_FILENO, &command->messages[command->message_count].content_size);
        command->message_count += 1;
        if (!command->messages[0].content)
            return (ft_printf("ft_ssl: Error: cannot read\n"), 0);
    }
    else
    {
        int fd = open(command->messages[0].input, O_RDONLY);
        if (fd < 0)
            return (ft_printf("ft_ssl: %s: No such file or directory\n", command->messages[0].input), 0);
        command->messages[0].content = read_fd(fd, &command->messages[0].content_size);
        close(fd);
        if (!command->messages[0].content)
            return (ft_printf("ft_ssl: Error: cannot read\n"), 0);
    }
    // process a base 64 input
    if (params.process_in_base64 && params.decode)
    {
        size_t outsize = 0;
        char *encoded = base64_decode(command->messages[0].content, command->messages[0].content_size, &outsize);
        if (!encoded)
            return 0;
        free(command->messages[0].content);
        command->messages[0].content = encoded;
        command->messages[0].content_size = outsize;
    }
    return (1);
}

t_des_params   des_process_command_flags(t_ssl_command *command)
{
    t_des_params params;

    params.decode = false;
    params.output_fd = STDOUT_FILENO;
    params.key = NULL;
    params.password = NULL;
    params.salt = NULL;
    params.iv = NULL;
    params.process_in_base64 = false;

    for (int i = 0; i < command->flag_count; i++)
    {
        if (command->flags[i].index == 0)
            params.process_in_base64 = true;
        else if (command->flags[i].index == 1)
            params.decode = true;
        else if (command->flags[i].index == 2)
            params.decode = false;
        else if (command->flags[i].index == 3 && command->flags[i].value && command->message_count == 0)
        {
            command->messages[command->message_count].input = ft_strdup(command->flags[i].value);
            command->messages[command->message_count].type = SSL_INPUT_FILE;
            command->message_count += 1;
        }
        else if (command->flags[i].index == 4)
        {
            params.output_fd = open(command->flags[i].value, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (params.output_fd < 0)
                return (ft_printf("ft_ssl: Error: %s: Cannot open output file\n", command->flags[i].value), params);
        }
        else if (command->flags[i].index == 5)
        {
            check_hex_len(command->flags[i].value, 16);
            uint64_t decoded = ft_atoi_base64(command->flags[i].value, "0123456789ABCDEF");
            params.key = ft_calloc(8, sizeof(char));
            if (!params.key)
                return (ft_printf("ft_ssl: Error: Memory error\n"), params);
            for (int j = 0; j < 8; j++)
            {
                uint8_t byte = decoded >> (uint8_t)(56 - (j * 8)) & 0xFF;
                params.key[j] = (char)byte;
            }
        }
        else if (command->flags[i].index == 6)
            params.password = command->flags[i].value;
        else if (command->flags[i].index == 7)
        {
            check_hex_len(command->flags[i].value, 16);
            uint64_t decoded = ft_atoi_base64(command->flags[i].value, "0123456789ABCDEF");
            // printf("decoded: %llx\n", decoded);
            params.salt = ft_calloc(8, sizeof(char));
            if (!params.salt)
                return (ft_printf("ft_ssl: Error: Memory error\n"), params);
            for (int j = 0; j < 8; j++)
            {
                uint8_t byte = decoded >> (uint8_t)(56 - (j * 8)) & 0xFF;
                params.salt[j] = (unsigned char)byte;
            }
        }
        else if (command->flags[i].index == 8)
        {
            check_hex_len(command->flags[i].value, 16);
            uint64_t decoded = ft_atoi_base64(command->flags[i].value, "0123456789ABCDEF");
            params.iv = ft_calloc(8, sizeof(char));
            if (!params.iv)
                return (ft_printf("ft_ssl: Error: Memory error\n"), params);
            for (int j = 0; j < 8; j++)
            {
                uint8_t byte = decoded >> (uint8_t)(56 - (j * 8)) & 0xFF;
                params.iv[j] = (char)byte;
            }
        }
        else if (command->flags[i].index == 9)
        {
            params.show_key = true;
        }
    }
    return (params);
}

void    free_params_des(t_des_params params)
{
    if (params.key)
        free(params.key);
    if (params.salt)
        free(params.salt);
    if (params.iv)
        free(params.iv);
    if (params.output_fd != STDOUT_FILENO)
        close(params.output_fd);
}

void    des_output_messages(t_ssl_command *command, t_des_params params, const char *algo_name)
{
    (void)algo_name;
    for (size_t i = 0; i < command->message_count; i++)
    {
        t_ssl_message   *message = &command->messages[i];
        size_t j = 0;
        if (params.process_in_base64 && !params.decode)
        {
            size_t outsize = 0;
            char *base64_decoded = base64_encode(command->messages[i].output, command->messages[i].output_size, &outsize);
            while (j < outsize)
            {
                write(params.output_fd, &(base64_decoded[j]), 1);
                j++;
            }
        }
        else
        {
            while (j < command->messages[i].output_size)
            {
                write(params.output_fd, &(message->output[j]), 1);
                j++;
            }
        }

    }
    return ;
}