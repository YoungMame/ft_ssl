#pragma once

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <stdint.h>
# include <inttypes.h>
# include <math.h>
# include <stdbool.h>
# include "libft.h"

# define SSL_MODE_SHA256 0
# define SSL_MODE_MD5 1

# define SSL_MODE_COUNT 2

/* function pointer for algorithm entry */
typedef int (*t_ssl_fptr)(int argc, char **argv, t_ssl_command *command);

/* metadata for each algorithm */
typedef struct s_ssl_algo {
    const char      *name;
    t_ssl_fptr      f;
    const int       nb_options;
    const char      **options;
    const char      **options_long;
    const char      **args;
    const char      **descriptions;
} t_ssl_algo;

/* array defined in a .c file */
extern const t_ssl_algo g_ssl_algos[];

typedef enum Ssl_input_type { 
    SSL_INPUT_FILE,
    SSL_INPUT_STRING,
    SSL_INPUT_STDIN
} t_ssl_input_type;

typedef struct  s_ssl_message {
    char                *input;
    char                *content;
    char                *output;
    t_ssl_input_type    type;
} t_ssl_message;

typedef struct s_ssl_flag {
    int     index;
    char    *value;
}   t_ssl_flag;

typedef struct s_ssl_command {
    t_ssl_flag      *flags
    int             flag_count;
    int             mode;
    size_t          message_count;
    t_ssl_command   messages[999];
}

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

// preprocess.c
char *get_preprocessed_message(char *message, size_t *total_len, bool is_size_big_endian);

// md5.c
int md5(int argc, char **argv, t_ssl_command *command);

// sha256.c
int sha256(int argc, char **argv, t_ssl_command *command);

//parse.c
int parse(int argc, char **argv, t_ssl_command *command);

// common.c

uint64_t get_message_len(const char *payload, size_t total_len);

uint32_t **allocate_chunk(size_t chunk_count);

void    free_chunk(uint32_t **M, size_t chunk_count);

uint32_t    left_rotate(uint32_t value, int shift);

uint32_t    right_rotate(uint32_t value, int shift);

// primes.c
int *generate_primes(int len);

// free
void    free_command(t_ssl_command *command);

// utils
int ft_pow(int number, int pow);

double ft_fabs(double number);

char    *read_fd(int fd);

// algos.c

void    init_algos();


