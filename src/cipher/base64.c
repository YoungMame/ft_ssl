# include "ft_ssl.h"

static const char *base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *malloc_buffer(size_t input_length) {
    /* number of base64 chars = 4 * ceil(input_length / 3) */
    size_t groups = (input_length + 2) / 3;
    size_t base64_chars_count = groups * 4;
    /* newlines every 64 chars (after encoding), so reserve space for them */
    size_t newline_count = base64_chars_count / 64;
    /* allocate base64 chars + newlines + terminating null */
    char *result = ft_calloc(base64_chars_count + newline_count + 1, sizeof(char));
    return result;
}

static char *malloc_decode_buffer(size_t input_length) {
    size_t bytes_groups_count = input_length / 4 + (input_length % 4 != 0);
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

char *base64_decode(const char *input, size_t input_len, size_t *out_size) {
    char *result = malloc_decode_buffer(input_len);
    if (!result)
        return ft_printf("ft_ssl: Error: Memory error\n"), NULL;

    unsigned char current_c = 0x0;

    size_t byte_index = 0;
    int bit_index = 0;

    for (size_t i = 0; i < input_len; i++)
    {
        unsigned char ch = input[i];

        /* padding: end of meaningful data */
        if (ch == '=')
            break;

        if (ch == '\n' || ch == '\r' || ch == '\t' || ch == ' ')
            continue;

        int index = get_base64_index((char)ch);
        /* ignore any other invalid characters */
        if (index == -1)
            continue;

        unsigned char index_char = (unsigned char)index;

        for (int j = 0; j < 6; j++)
        {
            unsigned char bit = (index_char >> (5 - j)) & 0x1u;
            current_c = (unsigned char)((current_c << 1) | bit);
            bit_index++;
            if (bit_index == 8)
            {
                result[byte_index] = (char)current_c;
                bit_index = 0;
                current_c = 0x0;
                byte_index++;
            }
        }
    }

    *out_size = byte_index;
    return result;
}

char *base64_encode(const char *input, const size_t input_len, size_t *out_size) {
    char *result = malloc_buffer(input_len);
    if (!result)
        return ft_printf("ft_ssl: Error: Memory error\n"), NULL;

    unsigned int base_index = 0x0;
    int          newline_count = 0;
    

    size_t byte_index = 0;
    int bit_index = 0;

    for (size_t i = 0; i < input_len; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            unsigned char bit = (input[i] >> (7 - j)) & 0x1u;
            base_index = (base_index << 1) | bit;
            bit_index++;
            if (bit_index == 6)
            {
                result[byte_index] = base64_chars[base_index];
                bit_index = 0;
                base_index = 0x0;
                byte_index++;
                if ((byte_index - newline_count) % 64 == 0)
                {
                    result[byte_index] = '\n';
                    byte_index++;
                    newline_count++;
                }
            }
        }
    }
    
    /* Get the last bits */
    if (bit_index > 0)
    {
        base_index = base_index << (6 - bit_index);
        result[byte_index] = base64_chars[base_index];
        byte_index++;
    }

    /* Base64 padding */
    if (input_len % 3 == 1)
    {
        result[byte_index++] = '=';
        result[byte_index++] = '=';
    }
    else if (input_len % 3 == 2)
    {
        result[byte_index++] = '=';
    }

    if (byte_index > 0 && result[byte_index - 1] == '\n')
        byte_index--;

    result[byte_index] = '\0';
    *out_size = byte_index;
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
        char    *output = base64_decode(command->messages[0].content, command->messages[0].content_size, &command->messages[0].output_size);
        if (!output)
            return (0);
        command->messages[0].output = output;
    }
    else
    {
        char    *output = base64_encode(command->messages[0].content, command->messages[0].content_size, &command->messages[0].output_size);
        if (!output)
            return (0);
        command->messages[0].output = output;
    }
    base64_output_messages(command, params, "base64");
     if (params.output_fd != STDOUT_FILENO)
        close(params.output_fd);
    
    return (1);
}