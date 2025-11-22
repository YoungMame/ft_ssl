#include "ft_ssl.h"

static uint8_t round_keys[11][64];

static uint8_t state[64];

// static void print_state(uint8_t *state[64]) {
//     ft_printf("State:\n");
//     ft_printf("________\n");
//     for (int i = 0; i < 8; i++) {
//         ft_printf("|");
//         for (int j = 0; j < 8; j++) {
//             ft_printf("%02x ", *(state[i * 8 + j]));
//         }
//         ft_printf("|\n");
//     }
//     ft_printf("________\n");
//     ft_printf("\n");
// }

static char    *append_h(char *hash, uint8_t value)
{
    char    *hex = ft_itoa_base_unsigned8(value, "0123456789abcdef", 2);
    if (!hex)
        return (NULL);
    char    *str = ft_strjoin(hash, hex);
    free(hex);
    return str;
}

// Append each hash values that result in hexadecimal format
static char    *final_hash_value(uint8_t values[64])
{
    char *digest = malloc(257 * sizeof(char));
    if (!digest)
        return NULL;
    digest[0] = '\0';

    for (int i = 0; i < 64; i++)
    {
        char *tmp = append_h(digest, values[i]);
        if (!digest)
            return (free(tmp), free(digest),NULL);
        free(digest);
        digest = tmp;

    }
    return (digest);
}

static uint8_t mul_byte(uint8_t a, uint8_t b)
{
    uint8_t res = 0;
    while (b)
    {
        if (b & 1) // if lowest bit is 1 (current bit of b)
            res ^= a;
        if (a & 0x80) // if highest bit is 1
            a = (a << 1) ^ 0x1d; // x^8 + x^4 + x^3 + x + 1 modulo GF(2^8)
        else
            a <<= 1; // process next bit
        b >>= 1; // shift b to process next bit
    }
    return (res);
}

// Substitute each byte with the value in the SBOX with the key corresponding to the byte value
static void sub_bytes(uint8_t _state[64]) {
    for (int row = 0; row < 8; row++) {
        for (int col = 0; col < 8; col++) {
            _state[row * 8 + col] = SBOX[(int)(_state[row * 8 + col])];
        }
    }
}

// Each value in the row is multiplied by the corresponding M value and XOR with others
// b0,0 = a0,0 XOR (9 • a0,1) XOR (2 • a0,2) XOR (5 • a0,3) XOR (8 • a0,4) XOR a0,5 XOR (4 • a0,6) XOR a0,7
static void mix_row(uint8_t row[8]) {
    uint8_t results[8] = {0};

    for (int col = 0; col < 8; col++)
    {
        results[col] ^= mul_byte(row[0], M[col * 8 + 0]) ^  mul_byte(row[1], M[col * 8 + 1]) ^
               mul_byte(row[2], M[col * 8 + 2]) ^  mul_byte(row[3], M[col * 8 + 3]) ^
               mul_byte(row[4], M[col * 8 + 4]) ^  mul_byte(row[5], M[col * 8 + 5]) ^
               mul_byte(row[6], M[col * 8 + 6]) ^  mul_byte(row[7], M[col * 8 + 7]);
    }

    for (int i = 0; i < 8; i++)
        row[i] = results[i];
}

static void mix_rows(uint8_t rows[64]) {
    for (int i = 0; i < 8; i++) {
        mix_row(&rows[i * 8]);
    }    
}

// static uint8_t get_shifted_column(uint8_t state[64], int index, int shift) {
//     uint8_t value = 0;
//     for (int i = 0; i < 8; i++) {
//         const left_rot = 1 & (index << (i));
//         const right_rot = 1 & (index >> (64 - i)); // contain the bit of the corresponding collumn
//         value |= right_rot;
//     }

//     value = (value << shift) | (value >> (8 - shift));
//     return (value);
// }

static void shift_columns(uint8_t _state[64]) {
    for (int col = 0; col < 8; col++) {
        uint8_t column[8];
        for (int row = 0; row < 8; row++)
            column[row] = _state[row * 8 + col];
        for (int row = 0; row < 8; row++)
            _state[row * 8 + col] = column[(row + col) % 8];
    }
}

// static uint8_t get_byte(uint64_t value, int byte_index) {
//     return (value >> (8 * (7 - byte_index))) & 0xFF;
// }

static void round_function(uint8_t _state[64], int round) {
    // SubBytes
    sub_bytes(_state);

    // Shift columns
    shift_columns(_state);

    // MixRows
    mix_rows(_state);

    // Add round key
    for (int i = 0; i < 8; i++) {
        for (int j = 0; j < 8; j++) {
            _state[i * 8 + j] ^= round_keys[round][i * 8 + j];
        }
    }
}

static void key_expension(uint8_t origin[64], int round) {
    uint8_t expanded_key[64] = {0};
    ft_memcpy(expanded_key, origin, 64 * sizeof(uint8_t));

    // SubBytes
    sub_bytes(expanded_key);

    // Shift Collumns
    shift_columns(expanded_key);

    // MixRows
    mix_rows(expanded_key);

    // Add round constant
    for (int i = 0; i < 8; i++) {
        expanded_key[i] ^= whirlpool_rc[round - 1][i];
    }

    ft_memcpy(round_keys[round], expanded_key, 64 * sizeof(uint8_t));
}


static void init_round_keys() {
    ft_bzero(round_keys[0], sizeof(uint8_t) * 64);

    for (int i = 0; i < 7; i++) {
        key_expension(round_keys[i], i + 1);
    }
}


static char *whirlpool_hashing(char *message) {
    char *preproc_message;
    size_t total_len;

    uint8_t H[64] = {0};

    // Preprocess the message in a char array where each byte is an element of the array
    preproc_message = get_preprocessed_message(message, &total_len, false);

    // Break the message into 512-bit chunks (each chunk is 64 bytes)
    size_t chunks_count = total_len / 64;

    uint8_t **M = allocate_chunk_height(chunks_count);
    if (!M)
        return (free(preproc_message), NULL);

    init_round_keys();

    // Break eeach chunk into a 8x8 matrix of 8-bit words
    for (size_t i = 0; i < chunks_count; i++)
    {
        for (size_t j = 0; j < 64; j++)
        {
            size_t byte_index = i * 64 + j;
            M[i][j] = (uint8_t)preproc_message[byte_index];
        }
    }

    // Process each 512-bit chunk
    for (size_t chunk = 0; chunk < chunks_count; chunk++)
    {
        /* copie correcte du bloc courant dans l'état (64 octets) */
        ft_memcpy(state, M[chunk], 64);

        /* première clé = chaining value H, puis expansion pour rounds 1..10 */
        ft_memcpy(round_keys[0], H, 64);
        for (int r = 1; r <= 10; r++)
            key_expension(round_keys[r - 1], r); /* génère round_keys[r] */

        /* 10 rounds */
        for (int round = 1; round <= 10; round++)
            round_function(state, round);

        /* Miyaguchi–Preneel update : H = H XOR M XOR W_H(M) */
        for (int i = 0; i < 64; i++)
            H[i] ^= state[i] ^ M[chunk][i];
    }

    char *digest = final_hash_value(H);

    if (!digest)
        return (free(preproc_message), free_chunk_height(M, chunks_count), NULL);

    return (free_chunk_height(M, chunks_count), free(preproc_message), digest);
}

int whirlpool(t_ssl_command *command) {
    t_hash_params   params = process_command_flags(command);
    int             success = process_command_inputs(command, params);
    if (!success)
        return (0); // TODO handle error

    for (size_t i = 0; i < command->message_count; i++)
    {
        char    *output = whirlpool_hashing(command->messages[i].content);
        if (!output)
            return (0);
        command->messages[i].output = output;
    }

    output_messages(command, params, "Whirlpool");

    return (1);
}