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
        printf("bit_len = %" PRIu64 "\n", bit_len);
    }
    return bit_len;
}

uint32_t **allocate_chunck(size_t chunck_count)
{
    uint32_t **M = malloc(chunck_count * sizeof(uint32_t*));

    for (size_t i = 0; i < chunck_count; i++)
    {
        M[i] = malloc(16 * sizeof(uint32_t));
    }
    return (M);
}

// Main MD5 function
// Using the preprocessed message, process it in 512-bit chunks
// Break message into 512-bit chunks
// Break each chunk into sixteen 32-bit words
// Use four words (A, B, C, D) to compute the message digest and set to initial constant values
char *md5(char *message) {
    char *preproc_message;
    uint32_t *K;
    uint32_t A;
    uint32_t B;
    uint32_t C;
    uint32_t D;
    size_t total_len;

    K = init_K();
        if (!K) return NULL;

    A = MD5_INITIAL_A;
    B = MD5_INITIAL_B;
    C = MD5_INITIAL_C;
    D = MD5_INITIAL_D;
    (void)A;
    (void)B;
    (void)C;
    (void)D;
    preproc_message = get_preprocessed_message(message, &total_len);
    uint64_t message_len = get_message_len(preproc_message, total_len);

    // Break the message into 512-bit chunks
    size_t chunks_count = total_len * 8 / MD5_CHUNK_SIZE;

    uint32_t **M = allocate_chunck(chunks_count);
    if (!M)
        return (free(K), NULL);

    for (size_t i = 0; i < chunks_count; i++)
    {
        for (size_t j = 0; j < 16; j++)
        {
            M[i][j] = M[i][j] | (32 << preproc_message[i * j])
                | (24 << preproc_message[i * j])
                | (16 << preproc_message[i * j])
                | (8 << preproc_message[i * j]);
        }
        printf("chunck[%i] = %ls\n", (int)i, M[i]);
    }


    printf("%" PRIu64 "\n", message_len);
    free(K);
    return (preproc_message);
}