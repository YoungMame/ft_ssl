# include "ft_ssl.h"

static char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *malloc_buffer(int input_length) {
    int bytes_groups_count = input_length / 3 + (input_length % 3 != 0);
    char *result = ft_calloc(bytes_groups_count * 4 + 1, sizeof(char));
    return result;
}

static char *malloc_decode_buffer(int input_length) {
    int bytes_groups_count = input_length / 4 + (input_length % 4 != 0);
    char *result = ft_calloc(bytes_groups_count * 3 + 1, sizeof(char));
    return result;
}

static int get_base64_index(char c) {
    for (int i = 0; i < 64; i++) {
        if (base64_chars[i] == c)
            return (i);
    }
    return (-1);
}

static char *base64_decode(const char *input) {
    int input_len = strlen(input);
    char *result = malloc_decode_buffer(input_len);
    if (!result)
        return ft_printf("ft_ssl: Error: Memory error\n"), NULL;

    char current_c = 0x0;

    int byte_index = 0;
    int bit_index = 0;

    for (int i = 0; i < input_len; i++)
    {
        int index = get_base64_index(input[i]);
        // manage = padding
        if (index == -1)
            break ;

        char index_char = (char)index;

        for (int j = 0; j < 6; j++)
        {
            char bit = (index_char >> (5 - j)) & 0x1;
            current_c = (current_c << 1) | bit;
            bit_index++;
            if (bit_index == 8)
            {
                // printf("Decoded char: %c\n", current_c);
                result[byte_index] = current_c;
                bit_index = 0;
                current_c = 0x0;
                byte_index++;
            }
        }
    }

    return result;
}

static char *base64_encode(const char *input) {
    int input_len = strlen(input);
    char *result = malloc_buffer(input_len);
    if (!result)
        return ft_printf("ft_ssl: Error: Memory error\n"), NULL;

    int base_index = 0x0;

    int byte_index = 0;
    int bit_index = 0;

    for (int i = 0; i < input_len; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            char bit = (input[i] >> (7 - j)) & 0x1;
            base_index = (base_index << 1) | bit;
            bit_index++;
            if (bit_index == 6)
            {
                result[byte_index] = base64_chars[base_index];
                bit_index = 0;
                base_index = 0x0;
                byte_index++;
            }
        }
    }
    
    // Get the last bits
    if (bit_index > 0)
    {
        base_index = base_index << (6 - bit_index);
        result[byte_index] = base64_chars[base_index];
        byte_index++;
    }

    // Base64 padding
    if (input_len % 3 == 1)
    {
        result[byte_index++] = '=';
        result[byte_index++] = '=';
    }
    else if (input_len % 3 == 2)
    {
        result[byte_index++] = '=';
    }

    return result;
}

int base64(t_ssl_command *command)
{
    t_base64_params   params = base64_process_command_flags(command);
    int             success = base64_process_command_inputs(command);
    if (!success)
        return (0);

    if (params.decode)
    {
        char    *output = base64_decode(command->messages[0].content);
        if (!output)
            return (0);
        command->messages[0].output = output;
    }
    else
    {
        char    *output = base64_encode(command->messages[0].content);
        if (!output)
            return (0);
        command->messages[0].output = output;
    }
    base64_output_messages(command, params, "base64");
     if (params.output_fd != STDOUT_FILENO)
        close(params.output_fd);
    
    return (1);
}