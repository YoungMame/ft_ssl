# include "ft_ssl.h"
# include "inttypes.h"

// static void pbin(uint64_t v)
// {
//     uint64_t mask = (uint64_t)1 << 63;
//     while (mask) {
//         printf("%d", (v & mask) ? 1 : 0);
//         mask >>= 1;
//     }
//     printf("\n");
// }

//static  void pbin32(uint32_t v)
// {
//     uint32_t mask = (uint32_t)1 << 31;
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

// Append each hash values that result in hexadecimal format
static uint8_t    *final_value(uint64_t *blocks, int chunk_count)
{
    uint8_t *final = ft_calloc(chunk_count * 8, sizeof(uint8_t));
    if (!final)
        return (NULL);

    for (int i = 0; i < chunk_count; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            uint8_t byte = (blocks[i] >> ((7 - j) * 8)) & 0xFF;
            final[i * 8 + j] = byte;
        }
    }
    return (final);
}

static void des_permute_choice1(uint64_t input, uint32_t *left, uint32_t *right)
{    
    *left = 0x0;
    *right = 0x0;
    for (int i = 0; i < 28; i++)
    {
        uint8_t pos = DES_PC1_LEFT[i];
        uint8_t bit = (input >> (64 - pos)) & 0x1;
        *left = (*left << 1) | bit;
    }
    for (int i = 0; i < 28; i++)
    {
        uint8_t pos = DES_PC1_RIGHT[i];
        uint8_t bit = (input >> (64 - pos)) & 0x1;
        *right = (*right << 1) | bit;
    }
    return ;
}

// output a 48 bits value
static uint64_t des_permute_choice2(uint32_t left, uint32_t right)
{
    uint64_t combined = ((uint64_t)left << 28) | (uint64_t)right; // 56 bits
    uint64_t output = 0;
    for (int i = 0; i < 48; i++)
    {
        uint8_t pos = DES_PC2[i];
        uint8_t bit = (combined >> (56 - pos)) & 0x1;
        output = (output << 1) | bit;
    }
    return output;
}

// Generate 16 subkeys from the main key
static uint64_t* des_key_schedule(uint64_t key)
{
    uint32_t left = 0x0;
    uint32_t right = 0x0;
    des_permute_choice1(key, &left, &right);


    uint64_t *subkeys = ft_calloc(16, sizeof(uint64_t));
    if (!subkeys)
        return (ft_printf("ft_ssl: Error: Memory errors\n") ,NULL);
    // For each of the 16 rounds
    for (int round = 0; round < 16; round++)
    {
        // Left shift amount for this round
        int shifts = DES_SHIFTS[round];

        // Perform the left shifts
        left = ((left << shifts) | (left >> (28 - shifts))) & 0x0FFFFFFF;
        right = ((right << shifts) | (right >> (28 - shifts))) & 0x0FFFFFFF;
        // printf("C %d: ", round + 1);
        // pbin(left);
        // printf("D %d: ", round + 1);
        // pbin(right);
        // Add subkey to the array
        subkeys[round] = des_permute_choice2(left, right);
        // printf("K %d: ", round + 1);
        // pbin(subkeys[round]);
    }
    return subkeys;
}

// ============================================ SUBKEYS GENERATION //

// Expand 32 bits to 48 bits
static uint64_t expansion_permutation(uint32_t half_block)
{
    uint64_t expanded = 0x0; // 48 bits
    for (int i = 0; i < 48; i++)
    {
        uint8_t pos = DES_EBOX[i];
        uint8_t bit = (half_block >> (32 - pos)) & 0x1;
        expanded = (expanded << 1) | bit;
    }
    return expanded;
}

static uint32_t keyed_substitution(uint64_t key)
{
    uint32_t output = 0;

    for (int i = 0; i < 8; i++)
    {
        uint8_t six = (key >> (42 - 6 * i)) & 0x3F;
        uint8_t row = ((six & 0x20) >> 4) | (six & 0x01);
        uint8_t col = (six >> 1) & 0x0F;
        uint8_t s = DES_SBOX[i][row][col] & 0x0F;
        output = (output << 4) | s;
    }
    return output;
}

static uint32_t permutation(uint32_t key)
{
    uint32_t permuted = 0x0;
    for (int i = 0; i < 32; i++)
    {
        uint8_t pos = DES_PBOX[i];
        uint8_t bit = (key >> (32 - pos)) & 0x1;
        permuted = (permuted << 1) | bit;
    }
    return permuted;
}

// subkey - 48 bits
static uint32_t des_round_function(uint32_t *left, uint32_t *right, uint64_t subkey)
{
    // store result
    uint32_t tmp = *right;

    // Function F
    uint64_t expanded = expansion_permutation(*right);
    (void)subkey;
    expanded ^= subkey;
    *right = keyed_substitution(expanded);
    *right = permutation(*right);

    *right = *left ^ *right;
    *left = tmp;
    return 0;
}

// ============================================ PER ROUND //

static uint64_t initial_permutation(uint64_t block)
{
    uint64_t permuted = 0x0;
    for (int i = 0; i < 64; i++)
    {
        uint8_t pos = DES_IP[i];
        uint8_t bit = (block >> (64 - pos)) & 0x1;
        permuted = (permuted << 1) | bit;
    }
    return permuted;
}

static uint64_t final_permutation(uint64_t block)
{
    uint64_t permuted = 0x0;
    for (int i = 0; i < 64; i++)
    {
        uint8_t pos = DES_FP[i];
        uint8_t bit = (block >> (64 - pos)) & 0x1;
        permuted = (permuted << 1) | bit;
    }
    return permuted;
}

static uint64_t des_encrypt_block(uint64_t plaintext, uint64_t *subkeys, bool decrypt)
{
    if (decrypt)
    {
        uint64_t reversed_subkeys[16];
        for (int i = 0; i < 16; i++)
        {
            reversed_subkeys[i] = subkeys[15 - i];
        }
        subkeys = reversed_subkeys;
    }

    plaintext = initial_permutation(plaintext);

    uint32_t left = (uint32_t)(plaintext >> 32) | 0x0;
    uint32_t right = (uint32_t)plaintext | 0x0;

    for (int round = 0; round < 16; round++)
    {
        des_round_function(&left, &right, subkeys[round]);
        // printf("L%d: ", round + 1);
        // pbin32(left);
        // printf("R%d: ", round + 1);
        // pbin32(right);
    }
    // 32 bits swap
    plaintext = ((uint64_t)right << 32) | left;
    // printf("After swap: ");
    // pbin(plaintext);
    plaintext = final_permutation(plaintext);
    // printf("After FP: ");
    // pbin(plaintext);
    return plaintext;
}

static uint64_t *des_allocate_chunks(char *message, bool no_pad, int *chunk_count, size_t message_len)
{
    *chunk_count = message_len / 8;
    if (message_len % 8 != 0)
        (*chunk_count) += 1;
    if (*chunk_count <= 0)
        return (NULL);
    uint64_t *chunks = ft_calloc(*chunk_count, sizeof(uint64_t));
    if (!chunks)
        return (ft_printf("ft_ssl: Error: Memory error\n"), NULL);

    int j = 0;
    uint8_t padding_diff = (u_int8_t)(no_pad ? 0x00 : 8 - (message_len % 8));
    while (j < *chunk_count)
    {
        chunks[j] = 0x0;
        for (int i = 0; i < 8; i++)
        {
            int index = j * 8 + i;
            uint8_t byte = (index < (int)message_len) ? (uint8_t)message[index] : padding_diff;
            chunks[j] |= (uint64_t)byte << ((7 - i) * 8);
        }
        j++;
    }

    return (chunks);
}

static uint64_t *des_ecb(uint64_t *blocks, int block_count, uint64_t *subkeys, bool decrypt)
{
    uint64_t *output = ft_calloc(block_count, sizeof(uint64_t));
    if (!output)
        return (NULL);

    for (int i = 0; i < block_count; i++)
    {
        uint64_t ciphertext = des_encrypt_block(blocks[i], subkeys, decrypt);
        // printf("Block %d ciphertext: ", i);
        // pbin(ciphertext);
        output[i] = ciphertext;
    }
    return (output);
}

// ============================================ PER BLOCK //

int des(t_ssl_command *command)
{
    t_des_params   params = des_process_command_flags(command);
    int             success = des_process_command_inputs(command, params);
    if (!success)
        return (0);

    if (command->message_count == 0 || !command->messages[0].content || command->messages[0].content_size == 0)
        return (free_params_des(params), ft_printf("ft_ssl: Error: No input provided\n"), 0);

    uint64_t key_numeric = 0;
    if (params.key)
    {
        // printf("Key provided: ");
        for (size_t i = 0; i < 8; i++)
        {
            // pbin8((uint8_t)params.key[i]);
            key_numeric = (key_numeric << 8) | (uint64_t)(uint8_t)params.key[i];
        }
    }
    else
    {
        if (!params.password)
            return (free_params_des(params), ft_printf("ft_ssl: Error: No key or password provided\n"), 0);
        char *generated_key = pbkdf2_8((const char *)params.password, (const char *)params.salt, hmac_sha256_prf, 10000, 8);
        if (!generated_key)
            return (free_params_des(params), 0);
        for (int i = 0; i < 8; i++)
        {
            key_numeric = (key_numeric << 8) | (uint64_t)(uint8_t)generated_key[i];
        }
    }
    uint64_t *subkeys = des_key_schedule(key_numeric);
    if (!subkeys)
        return (0);

    int blocks_count;
    uint64_t *blocks = des_allocate_chunks(command->messages[0].content, false, &blocks_count, command->messages[0].content_size);
    if (!blocks) return (free_params_des(params), free(subkeys), 0);

    uint64_t    *cipher = des_ecb(blocks, blocks_count, subkeys, params.decode);
    // printf("Cipher: ");
    // for (int i = 0; i < blocks_count; i++)
    // {
    //     printf("%s ", ft_itoa_base_unsigned64(cipher[i], "0123456789abcdef", 16));
    // }
    uint8_t *final = final_value(cipher, blocks_count);
    if (!final)
        return (free(blocks), free(subkeys), free(cipher), free_params_des(params), ft_printf("ft_ssl: Error: Memory error\n"), 0);

    free(blocks);
    free(subkeys);
    free(cipher);

    command->messages[0].output = (char *)final;
    command->messages[0].output_size = blocks_count * 8;

    // for (size_t i = 0; i < command->messages[0].output_size; i++)
    // {
    //     pbin8(command->messages[0].output[i]);
    // }
    // printf("\n");

    des_output_messages(command, params, "des");

    free_params_des(params);
    
    return (1);
}