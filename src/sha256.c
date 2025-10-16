# include "ft_ssl.h"


// Σ1 =
// (e rightrotate 6) xor
// (e rightrotate 11) xor
// (e rightrotate 25)

// Choice = (e and f) xor ((not e) and g)
// Σ0 =
// (a rightrotate 2) xor
// (a rightrotate 13) xor
// (a rightrotate 22)
// Majority =
// (a and b) xor (a and c) xor (b and c)

// We first implement sha256 used functions

static uint32_t    sigma0(uint32_t a)
{
    return (right_rotate(a, 2) ^ right_rotate(a, 13) ^ right_rotate(a, 22));
}

static uint32_t    sigma1(uint32_t e)
{
    return (right_rotate(e, 6) ^ right_rotate(e, 11) ^ right_rotate(e, 25));
}

static uint32_t    small_sigma0(uint32_t x)
{
    return (right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3));
}

static uint32_t    small_sigma1(uint32_t x)
{
    return (right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10));
}

static uint32_t    sha256_choice(uint32_t e, uint32_t f, uint32_t g)
{
    return ((e & f) ^ ((~e) & g));
}

static uint32_t    sha256_majority(uint32_t a, uint32_t b, uint32_t c)
{
    return ((a & b) ^ (a & c) ^ (b & c));
}

// Initialize array of K constants:
// first 32 bits of the fractional parts 
// of the cube roots of the first 64 primes
static uint32_t* sha256_init_K() {
    int *primes = generate_primes(64);

    uint32_t *K = ft_calloc(64, sizeof(uint32_t));
    if (!K)
        return (free(primes), NULL);
    for (int i = 0; i < 64; i++)
    {
        double prime = (double)primes[i];
        double cube_root = cbrt(prime);
        double fractional_part = cube_root - (uint32_t)cube_root;

        uint32_t scaled64 = (uint32_t)(fractional_part * pow(2, 32));
        uint32_t scaled = (uint32_t)scaled64;
        K[i] = scaled;
    }
    free(primes);
    return K;
}

static char    *append_h(char *hash, uint32_t value)
{
    char    *hex = ft_itoa_base_unsigned32(value, "0123456789abcdef", 8);
    if (!hex)
        return (NULL);
    char    *str = ft_strjoin(hash, hex);
    free(hex);
    return str;
}

static char    *final_hash_value(uint32_t h0, uint32_t h1, uint32_t h2, uint32_t h3, uint32_t h4, uint32_t h5, uint32_t h6, uint32_t h7)
{
    char *digest = ft_calloc(257, sizeof(char));
    if (!digest)
        return NULL;
    digest[0] = '\0';

    uint32_t values[8] = {h0, h1, h2, h3, h4, h5, h6, h7};
    for (int i = 0; i < 8; i++)
    {
        char *tmp = append_h(digest, values[i]);
        free(digest);
        if (!tmp)
        {
            free(digest);
            digest = NULL;
            return (NULL);
        }
        digest = tmp;
    }

    return digest;
}

// Main SHA256 function
// Using the preprocessed message, process it in 512-bit chunks
// Break message into 512-bit chunks
// Break each chunk into sixteen 32-bit words
static char *sha256_hashing(char *message) {
    char *preproc_message;
    size_t total_len;
    uint32_t *K;

    K = sha256_init_K();
    if (!K)
    return (NULL);

    // Preprocess the message in a char array where each byte is an element of the array
    preproc_message = get_preprocessed_message(message, &total_len, true);

    // Break the message into 512-bit chunks (each chunk is 64 bytes)
    size_t chunks_count = total_len / 64;

    uint32_t **M = allocate_chunk(chunks_count);
    if (!M)
        return (free(K), free(preproc_message), NULL);

    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t h0 = SHA256_INITIAL_A;
    uint32_t h1 = SHA256_INITIAL_B;
    uint32_t h2 = SHA256_INITIAL_C;
    uint32_t h3 = SHA256_INITIAL_D;
    uint32_t h4 = SHA256_INITIAL_E;
    uint32_t h5 = SHA256_INITIAL_F;
    uint32_t h6 = SHA256_INITIAL_G;
    uint32_t h7 = SHA256_INITIAL_H;

    // Break each chunk into 16 32 bits words
    for (size_t i = 0; i < chunks_count; i++)
    {
        for (size_t j = 0; j < 16; j++)
        {
            
            size_t word = i * 64;
            size_t byte = j * 4;
            size_t current_byte = word + byte;

            // Store bytes in the word big endian
            M[i][j] = ((uint32_t)(unsigned char)preproc_message[current_byte] << 24)
                | ((uint32_t)(unsigned char)preproc_message[current_byte + 1] << 16)
                | ((uint32_t)(unsigned char)preproc_message[current_byte + 2] << 8)
                | ((uint32_t)(unsigned char)preproc_message[current_byte + 3]);
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

    // Process each 512-bit chunk
    for (size_t chunk = 0; chunk < chunks_count; chunk++)
    {
        uint32_t W[64];

        // Copy first chunk into first 16 words of the message schedule array W
        for (size_t i = 0; i < 16; i++)
        {
            if (i < 16)
                W[i] = M[chunk][i];
        }

        // wi = (wi - 16) + sigma0(wi - 15) + (wi - 7) + sigma1(wi - 2)
        for (size_t i = 16; i < 64; i++)
        {
            W[i] = W[i - 16] + small_sigma0(W[i - 15]) + W[i - 7] + small_sigma1(W[i - 2]);
        }


        a = h0;
        b = h1;
        c = h2;
        d = h3;
        e = h4;
        f = h5;
        g = h6;
        h = h7;

        // Main loop: Compression
        // S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)
        // ch := (e and f) xor ((not e) and g)
        // temp1 := h + S1 + choice + k[i] + w[i]
        // S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)
        // maj := (a and b) xor (a and c) xor (b and c)
        // temp2 := S0 + maj
        for (size_t i = 0; i < 64; i++)
        {
            uint32_t    temp1 = h + sigma1(e) + sha256_choice(e, f, g) + K[i] + W[i];
            uint32_t    temp2 = sigma0(a) + sha256_majority(a, b, c);

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h0 = h0 + a;
        h1 = h1 + b;
        h2 = h2 + c;
        h3 = h3 + d;
        h4 = h4 + e;
        h5 = h5 + f;
        h6 = h6 + g;
        h7 = h7 + h;
    }



    // Output the hash in hexadecimal format
    char *digest = final_hash_value(h0, h1, h2, h3, h4, h5, h6, h7);
    if (!digest)
        return (free(preproc_message), free(K), free_chunk(M, chunks_count), NULL);

    free_chunk(M, chunks_count);
    free(preproc_message);
    free(K);
    return (digest);
}

int sha256(int argc, char **argv, t_ssl_command *command) {
    (void)argc;
    (void)argv;
    printf("SHA256 function\n");
    for (size_t i = 0; i < command->messages_count; i++)
    {
        char    *output = sha256_hashing(command->messages[i].content);
        if (!output)
            return (0);
        command->messages[i].output = output;
    }
    
    return (1);
}