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

typedef enum Ssl_input_type { 
    SLL_INPUT_FILE,
    SLL_INPUT_STRING,
    SLL_INPUT_STDIN
} t_ssl_input_type;

typedef struct  s_ssl_message {
    char                *input;
    char                *content;
    char                *output;
    t_ssl_input_type    type;
} t_ssl_message;

typedef struct  s_ssl_command {
    char            *name;
    char            *result;
    bool            is_quiet;
    bool            is_format_reversed;
    bool            is_outputing_stdin;
    size_t          messages_count;
    t_ssl_message   messages[999];
} t_ssl_command;

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
}

// md5_padding.c
char *get_preprocessed_message(char *message, size_t *total_len);

// md5_main.c
int md5(int argc, char **argv, t_ssl_command *command);

