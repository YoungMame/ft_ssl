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

// static int check_padding(uint64_t *blocks, int chunk_count)
// {
//     // get the last byte to get padding value
//     uint8_t padding_byte = (blocks[chunk_count - 1] >> 0) & 0xFF;
//     printf("Padding byte detected: 0x%02x (%d)\n", padding_byte, padding_byte);

//     if (padding_byte == 0 || padding_byte > 8)
//         return (-1);

//     bool valid_padding = true;
//     for (int i = 0; i < padding_byte && i < 8; i++) {
//         uint8_t byte = (blocks[chunk_count - 1] >> (i * 8)) & 0xFF;
//         if (byte != padding_byte) {
//             valid_padding = false;
//             break;
//         }
//     }

//     if (!valid_padding)
//         return (-1);
    
//     return ((int)padding_byte);

// }

// Append each hash values that result in hexadecimal format
static uint8_t    *final_value(uint64_t *blocks, int chunk_count, bool decrypt)
{
    // allocate buffer for final output
    uint8_t *final = ft_calloc(chunk_count * 8, sizeof(uint8_t));
    if (!final)
        return (NULL);

    // get all bytes from each 64-bit block
    for (int i = 0; i < chunk_count; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            uint8_t byte = (blocks[i] >> ((7 - j) * 8)) & 0xFF;
            final[i * 8 + j] = byte;
        }
    }

    size_t total_size = (size_t)chunk_count * 8;

    // remove padding if decrypting
    if (decrypt && total_size > 0)
    {
        uint8_t pad = final[total_size - 1];
        if (pad >= 1 && pad <= 8)
        {
            bool valid = true;
            for (size_t i = 0; i < pad; i++)
            {
                if (final[total_size - 1 - i] != pad)
                {
                    valid = false;
                    break;
                }
            }
            if (valid)
                total_size -= pad;
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

// Generate 16  from the main key
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
    uint64_t expanded = expansion_permutation(*right);
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
    uint64_t    reversed_subkeys[16];

    if (decrypt)
    {
        for (int i = 0; i < 16; i++)
        {
            reversed_subkeys[i] = subkeys[15 - i];
        }
    }
    else
    {
        for (int i = 0; i < 16; i++)
        {
            reversed_subkeys[i] = subkeys[i];
        }
    }

    plaintext = initial_permutation(plaintext);

    uint32_t left = (uint32_t)(plaintext >> 32) | 0x0;
    uint32_t right = (uint32_t)plaintext | 0x0;

    for (int round = 0; round < 16; round++)
    {
        des_round_function(&left, &right, reversed_subkeys[round]);
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

static uint64_t *des_allocate_chunks(char *message, int *chunk_count, size_t message_len, bool decrypt)
{
    size_t pad = 8 - (message_len % 8);
    if (pad == 0) pad = 8;

    size_t padded_len = message_len + (decrypt ? 0 : pad);
    *chunk_count = padded_len / 8;

    uint64_t *chunks = ft_calloc(*chunk_count, sizeof(uint64_t));
    if (!chunks)
        return (ft_printf("ft_ssl: Error: Memory error\n"), NULL);
    for (size_t j = 0; j < (size_t)*chunk_count; j++)
    {
        chunks[j] = 0x0;
        for (int i = 0; i < 8; i++)
        {
            int index = j * 8 + i;
            uint8_t byte = (index < (int)message_len) ? (uint8_t)message[index] : (decrypt ? 0 : (uint8_t)pad);
            chunks[j] |= (uint64_t)byte << ((7 - i) * 8);
        }
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

static uint64_t *des_cbc(uint64_t *blocks, int block_count, uint64_t *subkeys, bool decrypt, char *iv)
{
    if (!iv)
        return (ft_printf("ft_ssl: Error: IV is required for CBC mode\n"), NULL);

    uint64_t *output = ft_calloc(block_count, sizeof(uint64_t));
    if (!output)
        return (NULL);
    
    uint64_t    prev_cipher;
    prev_cipher = 0x0;
    for (int j = 0; j < 8; j++)
    {
        prev_cipher = (prev_cipher << 8) | (uint8_t)iv[j];
    }

    for (int i = 0; i < block_count; i++)
    {

        uint64_t xor_result = blocks[i];
        
        if (!decrypt) // encode
            xor_result ^= prev_cipher;

        uint64_t ciphertext = des_encrypt_block(xor_result, subkeys, decrypt);

        if (!decrypt) // encode
        {
            prev_cipher = ciphertext;
            output[i] = prev_cipher;
        }
        else // decode
        {
            output[i] = ciphertext ^ prev_cipher;
            prev_cipher = blocks[i];
        }
    }

    return (output);
}

static uint64_t *des_pcbc(uint64_t *blocks, int block_count, uint64_t *subkeys, bool decrypt, char *iv)
{
    if (!iv)
        return (ft_printf("ft_ssl: Error: IV is required for PCBC mode\n"), NULL);

    uint64_t *output = ft_calloc(block_count, sizeof(uint64_t));
    if (!output)
        return (NULL);
    
    uint64_t    prev_cipher;
    prev_cipher = 0x0;
    for (int j = 0; j < 8; j++)
    {
        prev_cipher = (prev_cipher << 8) | (uint8_t)iv[j];
    }

    for (int i = 0; i < block_count; i++)
    {

        uint64_t xor_result = blocks[i];
        
        if (!decrypt) // encode
            xor_result ^= prev_cipher;

        uint64_t ciphertext = des_encrypt_block(xor_result, subkeys, decrypt);

        if (!decrypt) // encode
        {
            output[i] = ciphertext;
            prev_cipher = ciphertext ^ blocks[i];
        }
        else // decode
        {
            output[i] = ciphertext ^ prev_cipher;
            prev_cipher = blocks[i] ^ output[i];
        }
    }

    return (output);
}

// cbc is a stream cipher mode so i will not edit my padding implementation for it

// static uint64_t *des_cfb(uint64_t *blocks, int block_count, uint64_t *subkeys, bool decrypt, char *iv, size_t message_len)
// {
//     uint64_t *output = ft_calloc(block_count, sizeof(uint64_t));
//     if (!output)
//         return (NULL);
    
//     uint64_t    ciphertext;
//     ciphertext = 0x0;
//     for (int j = 0; j < 8; j++)
//     {
//         ciphertext = (ciphertext << 8) | (uint8_t)iv[j];
//     }

//     for (int i = 0; i < block_count; i++)
//     {
//         ciphertext = des_encrypt_block(ciphertext, subkeys, decrypt);
//         if (!decrypt) // encode
//         {
//             uint64_t xor_result = blocks[i] ^ ciphertext;
//             output[i] = xor_result;
//             ciphertext = xor_result;
//         }
//         else // decode
//         {
//             output[i] = ciphertext ^  blocks[i];
//             ciphertext =  blocks[i];
//         }
//     }

//     return (output);
// }

static uint64_t *triple_des_cbc(uint64_t *blocks, int block_count, uint64_t *subkeys, bool decrypt, char *iv)
{
    if (!iv)
        return (ft_printf("ft_ssl: Error: IV is required for CBC mode\n"), NULL);

    uint64_t *output = ft_calloc(block_count, sizeof(uint64_t));
    if (!output)
        return (NULL);
    
    uint64_t    prev_cipher;
    prev_cipher = 0x0;
    for (int j = 0; j < 8; j++)
    {
        prev_cipher = (prev_cipher << 8) | (uint8_t)iv[j];
    }

    uint64_t   k1[16];
    uint64_t   k2[16];
    uint64_t   k3[16];

    for (int i = 0; i < 16; i++)
    {
        k1[i] = subkeys[i];
        k2[i] = subkeys[i + 16];
        k3[i] = subkeys[i + 32];
    }


    for (int i = 0; i < block_count; i++)
    {

        uint64_t xor_result = blocks[i];
        
        if (!decrypt) // encode
            xor_result ^= prev_cipher;

        uint64_t ciphertext = xor_result;

        if (!decrypt)
        {
            ciphertext = des_encrypt_block(ciphertext, k1, false); // E
            ciphertext = des_encrypt_block(ciphertext, k2, true);  // D
            ciphertext = des_encrypt_block(ciphertext, k3, false); // E
        }
        else
        {
            ciphertext = des_encrypt_block(ciphertext, k3, true);  // D
            ciphertext = des_encrypt_block(ciphertext, k2, false); // E
            ciphertext = des_encrypt_block(ciphertext, k1, true);  // D
        }

        if (!decrypt) // encode
        {
            prev_cipher = ciphertext;
            output[i] = prev_cipher;
        }
        else // decode
        {
            output[i] = ciphertext ^ prev_cipher;
            prev_cipher = blocks[i];
        }
    }

    return (output);
}

static uint64_t *triple_des_pcbc(uint64_t *blocks, int block_count, uint64_t *subkeys, bool decrypt, char *iv)
{
    if (!iv)
        return (ft_printf("ft_ssl: Error: IV is required for PCBC mode\n"), NULL);

    uint64_t *output = ft_calloc(block_count, sizeof(uint64_t));
    if (!output)
        return (NULL);
    
    uint64_t    prev_cipher;
    prev_cipher = 0x0;
    for (int j = 0; j < 8; j++)
    {
        prev_cipher = (prev_cipher << 8) | (uint8_t)iv[j];
    }

    uint64_t   k1[16];
    uint64_t   k2[16];
    uint64_t   k3[16];

    for (int i = 0; i < 16; i++)
    {
        k1[i] = subkeys[i];
        k2[i] = subkeys[i + 16];
        k3[i] = subkeys[i + 32];
    }


    for (int i = 0; i < block_count; i++)
    {

        uint64_t xor_result = blocks[i];
        
        if (!decrypt) // encode
            xor_result ^= prev_cipher;

        uint64_t ciphertext = xor_result;

        if (!decrypt)
        {
            ciphertext = des_encrypt_block(ciphertext, k1, false); // E
            ciphertext = des_encrypt_block(ciphertext, k2, true);  // D
            ciphertext = des_encrypt_block(ciphertext, k3, false); // E
        }
        else
        {
            ciphertext = des_encrypt_block(ciphertext, k3, true);  // D
            ciphertext = des_encrypt_block(ciphertext, k2, false); // E
            ciphertext = des_encrypt_block(ciphertext, k1, true);  // D
        }

        if (!decrypt) // encode
        {
            output[i] = ciphertext;
            prev_cipher = ciphertext ^ blocks[i];
        }
        else // decode
        {
            output[i] = ciphertext ^ prev_cipher;
            prev_cipher = blocks[i] ^ output[i];
        }
    }

    return (output);
}

static uint64_t *triple_des_ecb(uint64_t *blocks, int block_count, uint64_t *subkeys, bool decrypt)
{
    uint64_t *output = ft_calloc(block_count, sizeof(uint64_t));
    if (!output)
        return (NULL);

    uint64_t   k1[16];
    uint64_t   k2[16];
    uint64_t   k3[16];

    for (int i = 0; i < 16; i++)
    {
        k1[i] = subkeys[i];
        k2[i] = subkeys[i + 16];
        k3[i] = subkeys[i + 32];
    }

    for (int i = 0; i < block_count; i++)
    {
        uint64_t ciphertext = blocks[i];

        if (!decrypt)
        {
            ciphertext = des_encrypt_block(ciphertext, k1, false); // E
            ciphertext = des_encrypt_block(ciphertext, k2, true);  // D
            ciphertext = des_encrypt_block(ciphertext, k3, false); // E
        }
        else
        {
            ciphertext = des_encrypt_block(ciphertext, k3, true);  // D
            ciphertext = des_encrypt_block(ciphertext, k2, false); // E
            ciphertext = des_encrypt_block(ciphertext, k1, true);  // D
        }
        
        // printf("Block %d ciphertext: ", i);
        // pbin(ciphertext);
        output[i] = ciphertext;
    }
    return (output);
}

// ============================================ PER BLOCK //

int des(t_ssl_command *command)
{
    // 3DES ? include 3DES-PCBC (mode 13)
    bool            is_triple = (command->mode == 9 || command->mode == 10 || command->mode == 11 || command->mode == 13);

    t_des_params    params = des_process_command_flags(command, is_triple);
    int             success = des_process_command_inputs(command, params);
    if (!success)
        return (free_params_des(params), 0);

    if (command->message_count == 0 || !command->messages[0].content || command->messages[0].content_size == 0)
        return (free_params_des(params), ft_printf("ft_ssl: Error: No input provided\n"), 0);

    uint64_t key_numeric = 0x0;
    uint64_t second_key_numeric = 0x0;
    uint64_t third_key_numeric = 0x0;
    if (params.key)
    {
        // printf("Key provided: ");
        for (size_t i = 0; i < 8; i++)
            key_numeric = (key_numeric << 8) | (uint64_t)(uint8_t)params.key[i];
        if (is_triple)
        {
            for (size_t i = 8; i < 16; i++)
                second_key_numeric = (second_key_numeric << 8) | (uint64_t)(uint8_t)params.key[i];
            for (size_t i = 16; i < 24; i++)
                third_key_numeric = (third_key_numeric << 8) | (uint64_t)(uint8_t)params.key[i];
        }
    }
    else
    {
        if (!params.password)
            return (free_params_des(params), ft_printf("ft_ssl: Error: No key or password provided\n"), 0);
        if (!params.salt)
            return (free_params_des(params), ft_printf("ft_ssl: Error: No salt provided for key derivation\n"), 0);
        size_t key_derive_len = is_triple ? 24 : 8;
        uint8_t         *generated_key = pbkdf2((const char *)params.password, ft_strlen(params.password), (const char *)params.salt, 8, hmac_hash256, 32, 1000, key_derive_len);
        if (!generated_key)
            return (free_params_des(params), 0);

        for (int i = 0; i < 8; i++)
            key_numeric = (key_numeric << 8) | generated_key[i];

        if (is_triple)
        {
            for (int i = 8; i < 16; i++)
            {
                second_key_numeric = (second_key_numeric << 8) | generated_key[i];
            }
            for (int i = 16; i < 24; i++)
            {
                third_key_numeric = (third_key_numeric << 8) | generated_key[i];
            }
        }
        free(generated_key);
    }
    uint64_t *subkeys = des_key_schedule(key_numeric);
    if (!subkeys)
        return (free_params_des(params), 0);
    if (is_triple)
    {
        uint64_t *second_subkeys = des_key_schedule(second_key_numeric);
        uint64_t *third_subkeys = des_key_schedule(third_key_numeric);
        if (!second_subkeys || !third_subkeys)
            return (free(subkeys), free(second_subkeys), free(third_subkeys), free_params_des(params), 0);

        uint64_t *all_subkeys = ft_calloc(48, sizeof(uint64_t));
        if (!all_subkeys)
            return (free(subkeys), free(second_subkeys), free(third_subkeys), free_params_des(params), ft_printf("ft_ssl: Error: Memory error\n"), 0);
        for (int i = 0; i < 16; i++)
        {
            all_subkeys[i] = subkeys[i];
            all_subkeys[i + 16] = second_subkeys[i];
            all_subkeys[i + 32] = third_subkeys[i];
        }
        free(subkeys);
        free(second_subkeys);
        free(third_subkeys);
        subkeys = all_subkeys;
    }

    int blocks_count;
    uint64_t *blocks = des_allocate_chunks(command->messages[0].content, &blocks_count, command->messages[0].content_size, params.decode);
    if (!blocks) return (free_params_des(params), free(subkeys), 0);

    uint64_t    *cipher = NULL;

    if (command->mode == 7 || command->mode == 6) // des-ecb
        cipher = des_ecb(blocks, blocks_count, subkeys, params.decode); 
    else if (command->mode == 8) // des-cbc
        cipher = des_cbc(blocks, blocks_count, subkeys, params.decode, params.iv);
    else if (command->mode == 9 || command->mode == 10) // des3-cbc
        cipher = triple_des_cbc(blocks, blocks_count, subkeys, params.decode, params.iv);
    else if (command->mode == 11) // des3-ecb
        cipher = triple_des_ecb(blocks, blocks_count, subkeys, params.decode);
    else if (command->mode == 12) // des-pcbc
        cipher = des_pcbc(blocks, blocks_count, subkeys, params.decode, params.iv);
    else if (command->mode == 13) // des3-pcbc
        cipher = triple_des_pcbc(blocks, blocks_count, subkeys, params.decode, params.iv);
    
    if (!cipher)
        return (free(blocks), free(subkeys), free_params_des(params), 0);

    uint8_t *final = final_value(cipher, blocks_count, params.decode);
    if (!final)
        return (free(blocks), free(subkeys), free(cipher), free_params_des(params), 0);

    free(blocks);
    free(subkeys);
    free(cipher);

    command->messages[0].output = (char *)final;

    // trim output if decoding
    size_t actual_size = (size_t)blocks_count * 8;
    if (params.decode && actual_size > 0)
    {
        uint8_t pad = final[actual_size - 1];
        if (pad >= 1 && pad <= 8)
        {
            bool valid = true;
            for (size_t i = 0; i < pad; i++)
            {
                if (final[actual_size - 1 - i] != pad)
                {
                    valid = false;
                    break;
                }
            }
            if (valid)
                actual_size -= pad;
        }
    }
    command->messages[0].output_size = actual_size;

    // for (size_t i = 0; i < command->messages[0].output_size; i++)
    // {
    //     pbin8(command->messages[0].output[i]);
    // }
    // printf("\n");
    if (params.show_key)
    {
        if (params.salt)
        {
            ft_printf("salt=");
            for (int i = 0; i < 8; i++)
            {
                char *salt_hex = ft_itoa_base_unsigned8((uint8_t)params.salt[i], "0123456789ABCDEF", 2);
                ft_printf("%s" ,salt_hex);
                free(salt_hex);
            }
            ft_printf("\n");
        }
        if (key_numeric)
        {
            char *key_hex = ft_itoa_base_unsigned64(key_numeric, "0123456789ABCDEF", 16);
            if (!key_hex)
                return (ft_printf("ft_ssl: Error: Memory Error\n"), free_params_des(params), 0);
            ft_printf("key=%s\n", key_hex);
            free(key_hex);
        }
        if (params.iv)
        {
            char *iv_hex = ft_itoa_base_unsigned64(ft_atoi_base64(params.iv, "0123456789ABCDEF"), "0123456789ABCDEF", 16);
            if (!iv_hex)
                return (ft_printf("ft_ssl: Error: Memory Error\n"), free_params_des(params), 0);
            ft_printf("iv=%s\n", iv_hex);
            free(iv_hex);
        }
    }
    else
        des_output_messages(command, params, "des");

    free_params_des(params);
    
    return (1);
}
