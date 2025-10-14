#include "ft_ssl.h"

// Use the sine of each integer in radian as random values
// for each k[i]:
// K[i] := floor(232 × abs(sin(i + 1)))
uint32_t* init_K() {
    uint32_t *K = malloc(64 * sizeof(uint32_t));
    if (!K) return NULL;
    for (int i = 0; i < 64; i++)
    {
        K[i] = (uint32_t)(fabs(sin(i + 1)) * pow(2, 32));
    }
    return K;
}

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

// Allocate the good number of chunks and the words in it
uint32_t **allocate_chunk(size_t chunk_count)
{
    uint32_t **M = malloc(chunk_count * sizeof(uint32_t*));
    if (!M) return NULL;

    for (size_t i = 0; i < chunk_count; i++)
    {
        M[i] = malloc(16 * sizeof(uint32_t));
        if (!M[i])
        {
            for (size_t j = 0; j < i; j++)
                free(M[j]);
            free(M);
            return NULL;
        }
    }
    return (M);
}

uint32_t    left_rotate(uint32_t value, int shift)
{
    return (value << shift) | (value >> (32 - shift));
}

// Main MD5 function
// Using the preprocessed message, process it in 512-bit chunks
// Break message into 512-bit chunks
// Break each chunk into sixteen 32-bit words
// Use four words (A, B, C, D) to compute the message digest and set to initial constant values
char *md5_hashing(char *message) {
    char *preproc_message;
    uint32_t *K;
    size_t total_len;

    K = init_K();
        if (!K) return NULL;

    // Preprocess the message in a char array where each byte is an element of the array
    preproc_message = get_preprocessed_message(message, &total_len);

    // Break the message into 512-bit chunks (each chunk is 64 bytes)
    size_t chunks_count = total_len / 64;

    uint32_t **M = allocate_chunk(chunks_count);
    if (!M)
    {
        free(K);
        return NULL;
    }

    // Break each chunk into 16 32 bits words
    for (size_t i = 0; i < chunks_count; i++)
    {
        for (size_t j = 0; j < 16; j++)
        {
            
            size_t word = i * 64;
            size_t byte = j * 4;
            size_t current_byte = word + byte;

            // Store bytes in the word
            M[i][j] = ((uint32_t)preproc_message[current_byte])
                | ((uint32_t)preproc_message[current_byte + 1] << 8)
                | ((uint32_t)preproc_message[current_byte + 2] << 16)
                | ((uint32_t)preproc_message[current_byte + 3] << 24);
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
                F = (d & b) | ((~d) & c);
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
    char *digest = malloc((32 + 1) * sizeof(char));
    if (!digest)
    {
        for (size_t i = 0; i < chunks_count; i++)
            free(M[i]);
        free(M);
        free(K);
        return(NULL);
    }

    sprintf(digest, "%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x", 0xff & (h0 >> 0), 0xff & (h0 >> 8), 0xff & (h0 >> 16), 0xff & (h0 >> 24),
            0xff & (h1 >> 0), 0xff & (h1 >> 8), 0xff & (h1 >> 16), 0xff & (h1 >> 24),
            0xff & (h2 >> 0), 0xff & (h2 >> 8), 0xff & (h2 >> 16), 0xff & (h2 >> 24),
            0xff & (h3 >> 0), 0xff & (h3 >> 8), 0xff & (h3 >> 16), 0xff & (h3 >> 24));

    for (size_t i = 0; i < chunks_count; i++)
        free(M[i]);
    free(M);
    free(K);
    
    return (digest);
}

int md5(int argc, char **argv, t_ssl_command *command) {
    (void)argc;
    (void)argv;
    for (size_t i = 0; i < command->messages_count; i++)
    {
        command->messages[i].output = md5_hashing(command->messages[i].content);
    }
    
    return (1);
}