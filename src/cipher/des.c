# include "ft_ssl.h"
# include "inttypes.h"

static void des_permute_choice1(uint64_t input, uint32_t *left, uint32_t *right)
{    
    // left
    for (int i = 0; i < 28; i++)
    {
        uint8_t permuted_bit = (input << (56 - DES_PC1_LEFT[i])) & 0x1;
        *left = (*left << 1) | permuted_bit;
    }
    // right
    for (int i = 0; i < 28; i++)
    {
        uint8_t permuted_bit = (input << (56 - DES_PC1_RIGHT[i])) & 0x1;
        *right = (*right << 1) | permuted_bit;
    }
    return ;
}

// output a 48 bits value
static uint64_t des_permute_choice2(uint32_t left, uint32_t right)
{
    uint64_t output = 0x0;
    // left
    for (int i = 0; i < 48; i++)
    {
        uint8_t pos = DES_PC2[i] ;
        uint8_t permuted_bit = ((pos > 27 ? left : right) << (56 - pos)) & 0x1;
        output = (output << 1) | permuted_bit;
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

        // Add subkey to the array
        subkeys[round] = des_permute_choice2(left, right);
    }
    return subkeys;
}

// ======================================= SUBKEYS GENERATION //

// Expand 32 bits to 48 bits
static uint64_t expansion_permutation(uint32_t half_block)
{
    uint64_t expanded = 0x0; // 48 bits
    for (int i = 0; i < 48; i++)
    {
        uint8_t pos = DES_EBOX[i] ;
        uint8_t bit = (half_block >> (32 - pos)) & 0x1;
        expanded = (expanded << 1) | bit;
    }
    return expanded;
}

static uint32_t keyed_substitution(uint64_t key)
{
    uint8_t split[8] = {}; // 48 bit key splitted in 4 bits values

    for (size_t i = 0; i < 8; i++)
    {
        // uint8_t six_bits_v = 0xFC & key;
        uint8_t row = (0x84 & key) >> 2 | (0x01 & key);
        uint8_t r_row = 0x0 | ((row << 1) & (row >> 1) >> 2) | ((row & 0x1) >> 7);
        uint8_t col = 0x78 & key;
        uint8_t r_col = (col >> 3) & 0x0F;
        uint8_t f_bits_v = DES_SBOX[i][r_row][r_col];
        split[i] = f_bits_v;
        key = key << 6;
    }
    
    uint32_t output = 0x0; // 32 bits key
    for (size_t i = 0; i < 8; i++)
    {
        // add every 4 bits value according to the 32 bits output
        output = (output << 4) | split[i];
    }

    return output;
}

static uint32_t permutation(u_int32_t key)
{
    uint32_t permuted = 0x0;
    for (int i = 0; i < 32; i++)
    {
        uint8_t pos = DES_PBOX[i] ;
        uint8_t bit = (key >> (32 - pos)) & 0x1;
        permuted = (permuted << 1) | bit;
    }
    return permuted;
}

// subkey - 48 bits
static uint32_t des_round_function(uint32_t *left, uint32_t *right, uint64_t subkey)
{
    // store result
    uint32_t result = *right;

    // Function F
    uint64_t expanded = expansion_permutation(*right);
    expanded ^= subkey;
    result = keyed_substitution(expanded);
    result = permutation(result);

    // Swap left and right
    uint32_t tmp = *right;
    *right = *left ^ result;
    *left = tmp;
    return 0;
}

// ======================================= PER ROUND //

static uint64_t initial_permutation(uint64_t block)
{
    uint64_t permuted = 0x0;
    for (int i = 0; i < 64; i++)
    {
        uint8_t pos = DES_IP[i] ;
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
        uint8_t pos = DES_FP[i] ;
        uint8_t bit = (block >> (64 - pos)) & 0x1;
        permuted = (permuted << 1) | bit;
    }
    return permuted;
}

static uint64_t des_encrypt_block(uint64_t plaintext, uint64_t *subkeys)
{
    plaintext = initial_permutation(plaintext);

    uint32_t left = (plaintext >> 32) & 0xFFFFFFFF;
    uint32_t right = plaintext & 0xFFFFFFFF;
    for (int round = 0; round < 16; round++)
    {
        des_round_function(&left, &right, subkeys[round]);
    }
    // 32 bits swap
    plaintext = ((uint64_t)right << 32) | left;
    plaintext = final_permutation(plaintext);
    return plaintext;
}

// ======================================= PER BLOCK //

int des(t_ssl_command *command)
{
    t_des_params   params = des_process_command_flags(command);
    int             success = des_process_command_inputs(command);
    if (!success)
        return (0);

    uint64_t key = 0x133457799BBCDFF1u;
    uint64_t plaintext = 0x0123456789ABCDEFu;
    uint64_t expected = 0x85E813540F0AB405u;
    uint64_t *subkeys = des_key_schedule(key);
    if (!subkeys)
        return (0);
    uint64_t ciphertext = des_encrypt_block(plaintext, subkeys);
    printf("val = 0x%" PRIx64 "\n", ciphertext);
    printf("expected = 0x%" PRIx64 "\n", expected);
    free(subkeys);
    des_output_messages(command, params, "des");
     if (params.output_fd != STDOUT_FILENO)
        close(params.output_fd);
    
    return (1);
}