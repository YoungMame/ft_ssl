#include "ft_ssl.h"



// Read from stdin if no messages were added from arguments, or if -p flag is used
// if (command->messages_count == 0 || command->is_outputing_stdin)
// {
//     t_ssl_message   message;
//     message.type = SSL_INPUT_STDIN;
//     message.input = ft_strdup("stdin");
//     message.output = NULL;

//     message.content = read_fd(STDIN_FILENO);
//     if (!message.content)
//         return (free_command(command), 1);
//     command->messages[command->messages_count] = message;
//     command->messages_count++;
// }

static char    *append_h(char *hash, uint32_t value)
{
    // Bit swap to little-endian
    uint32_t o1, o2, o3, o4;
    o1 = (0xFF000000 & (value << 24));
    o2 = (0x00FF0000 & (value << 8));
    o3 = (0x0000FF00 & (value >> 8));
    o4 = (0x000000FF & (value >> 24));
    uint32_t little_endian_value = o1 | o2 | o3 | o4;
    char    *hex = ft_itoa_base_unsigned32(little_endian_value, "0123456789abcdef", 8);
    if (!hex)
        return (NULL);
    char    *str = ft_strjoin(hash, hex);
    free(hex);
    return str;
}

// Append each hash values that result in hexadecimal format
static char    *final_hash_value(uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3)
{
    char *digest = malloc(257 * sizeof(char));
    if (!digest)
        return NULL;
    digest[0] = '\0';

    uint32_t values[4] = {h0, h1, h2, h3};
    for (int i = 0; i < 4; i++)
    {
        char *tmp = append_h(digest, values[i]);
        if (!digest)
            return (free(tmp), free(digest),NULL);
        free(digest);
        digest = tmp;

    }

    return (digest);
}

// Use the sine of each integer in radian as random values
// for each k[i]:
// K[i] := floor(232 × abs(sin(i + 1)))
static uint32_t* md5_init_K() {
    uint32_t *K = malloc(64 * sizeof(uint32_t));
    if (!K)
        return NULL;
    for (int i = 0; i < 64; i++)
    {
        K[i] = (uint32_t)(ft_fabs(sin(i + 1)) * ft_pow(2, 32));
    }
    return (K);
}

// Main MD5 function
// Using the preprocessed message, process it in 512-bit chunks
// Break message into 512-bit chunks
// Break each chunk into sixteen 32-bit words
// Use four words (A, B, C, D) to compute the message digest and set to initial constant values
static char *md5_hashing(char *message) {
    char *preproc_message;
    uint32_t *K;
    size_t total_len;

    K = md5_init_K();
    if (!K)
        return (NULL);

    // Preprocess the message in a char array where each byte is an element of the array
    preproc_message = get_preprocessed_message(message, &total_len, false);

    // Break the message into 512-bit chunks (each chunk is 64 bytes)
    size_t chunks_count = total_len / 64;

    uint32_t **M = allocate_chunk(chunks_count);
    if (!M)
        return (free(K), free(preproc_message), NULL);

    // Break each chunk into 16 32 bits words
    for (size_t i = 0; i < chunks_count; i++)
    {
        for (size_t j = 0; j < 16; j++)
        {
            
            size_t word = i * 64;
            size_t byte = j * 4;
            size_t current_byte = word + byte;

            // Store bytes in the word
            M[i][j] = ((uint32_t)(unsigned char)preproc_message[current_byte])
                | ((uint32_t)(unsigned char)preproc_message[current_byte + 1] << 8)
                | ((uint32_t)(unsigned char)preproc_message[current_byte + 2] << 16)
                | ((uint32_t)(unsigned char)preproc_message[current_byte + 3] << 24);
        }

        // DEBUG
        // printf("chunk[%zu]: ", i);
        // for (size_t j = 0; j < 16; j++)
        // {
        //     printf("%08x ", M[i][j]);
        // }
        // printf("\n");
    }

    // Main loop

    // Round 1 : F(X,Y,Z) = (X & Y) | (~X & Z) and g = j
    // Round 2 : G(X,Y,Z) = (X & Z) | (Y & ~Z) and g := (5×i + 1) mod 16
    // Round 3 : H(X,Y,Z) = X ^ Y ^ Z and g := (3×i + 5) mod 16
    // Round 4 : I(X,Y,Z) = Y ^ (X | ~Z) and g := (7×i) mod 16

    // A = h0, B = h1, C = h2, D = h3

    uint32_t h0;
    uint32_t h1;
    uint32_t h2;
    uint32_t h3;
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t F;
    uint32_t g;

    h0 = MD5_INITIAL_A;
    h1 = MD5_INITIAL_B;
    h2 = MD5_INITIAL_C;
    h3 = MD5_INITIAL_D;

    // Process each 512-bit chunk
    for (size_t chunk = 0; chunk < chunks_count; chunk++)
    {
        // Initialize words for this chunk
        a = h0;
        b = h1;
        c = h2;
        d = h3;
        
        // Main loop: 64 operations in 4 rounds so 16 operations each
        for (size_t i = 0; i < 64; i++)
        {
            int shifts[] = MD5_SHIFT_PER_ROUND;
            
            if (i < 16) // Round 1
            {
                F = (b & c) | ((~b) & d);
                g = i;
            }
            else if (i < 32) // Round 2
            {
                F = (b & d) | (c & ~d);
                g = (5 * i + 1) % 16;
            }
            else if (i < 48) // Round 3
            {
                F = b ^ c ^ d;
                g = (3 * i + 5) % 16;
            }
            else // Round 4
            {
                F = c ^ (b | (~d));
                g = (7 * i) % 16;
            }
            
            F = F + a + K[i] + M[chunk][g];
            a = d;
            d = c;
            c = b;
            b = b + left_rotate(F, shifts[i]);
        }
        
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    // Output the hash in hexadecimal format
    char *digest = final_hash_value(h0, h1, h2, h3);

    if (!digest)
        return (free(preproc_message), free(K), free_chunk(M, chunks_count), NULL);

    return (free_chunk(M, chunks_count), free(K), free(preproc_message), digest);
}

int md5(t_ssl_command *command) {
    t_hash_params   params = process_command_flags(command);
    int             success = process_command_inputs(command, params);
    if (!success)
        return (0); // TODO handle error

    for (size_t i = 0; i < command->message_count; i++)
    {
        char    *output = md5_hashing(command->messages[i].content);
        if (!output)
            return (0);
        command->messages[i].output = output;
    }

    output_messages(command, params, "MD5");
    
    return (1);
}