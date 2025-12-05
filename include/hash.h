# pragma once

typedef struct s_hash_params {
    bool    should_read_stdin;
    bool    is_quiet;
    bool    is_reversed;
}   t_hash_params;

typedef struct s_ssl_command t_ssl_command;

t_hash_params   hash_process_command_flags(t_ssl_command *command);

int             hash_process_command_inputs(t_ssl_command *command, t_hash_params params);

void            hash_output_messages(t_ssl_command *command, t_hash_params params, const char *algo_name);

// hash/common.c

uint64_t get_message_len(const char *payload, size_t total_len);

uint32_t **allocate_chunk(size_t chunk_count);

uint8_t **allocate_chunk_height(size_t chunk_count);

void    free_chunk(uint32_t **M, size_t chunk_count);

void    free_chunk_height(uint8_t **M, size_t chunk_count);

// hash/primes.c
int *generate_primes(int len);

// hash/preprocess.c
char *get_preprocessed_message(char *message, size_t message_len, size_t *total_len, bool is_size_big_endian);
char *get_preprocessed_message_whirlpool(char *message, size_t message_len, size_t *total_len);

// MD5 CONSTANTS
# define MD5_CHUNK_SIZE 512
# define MD5_INITIAL_A 0x67452301
# define MD5_INITIAL_B 0xefcdab89
# define MD5_INITIAL_C 0x98badcfe
# define MD5_INITIAL_D 0x10325476
# define MD5_SHIFT_PER_ROUND { \
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, \
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, \
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, \
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 \
};

// SHA256 CONSTANTS

# define MD5_CHUNK_SIZE 512
# define SHA256_INITIAL_A 0x6a09e667
# define SHA256_INITIAL_B 0xbb67ae85
# define SHA256_INITIAL_C 0x3c6ef372
# define SHA256_INITIAL_D 0xa54ff53a
# define SHA256_INITIAL_E 0x510e527f
# define SHA256_INITIAL_F 0x9b05688c
# define SHA256_INITIAL_G 0x1f83d9ab
# define SHA256_INITIAL_H 0x5be0cd19

// Round constants
extern const uint8_t M[64];

 //Whirlpool T box = S box combined with multiplication in GF(2^8)
extern const uint8_t SBOX[256];