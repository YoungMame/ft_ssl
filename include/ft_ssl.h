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
# include "hash.h"
# include "cipher.h"

# define SSL_MODE_COUNT 8

typedef enum ssl_input_type { 
    SSL_INPUT_FILE,
    SSL_INPUT_STRING,
    SSL_INPUT_STDIN
} t_ssl_input_type;

typedef struct  s_ssl_message {
    char                *input;
    char                *content;
    char                *output;
    size_t              content_size;
    size_t              output_size;
    t_ssl_input_type    type;
} t_ssl_message;

typedef struct s_ssl_flag {
    int     index;
    char    *value;
}   t_ssl_flag;

typedef struct s_ssl_command {
    t_ssl_flag      *flags;
    int             flag_count;
    int             mode;
    size_t          message_count;
    t_ssl_message   messages[999];
}   t_ssl_command;

/* function pointer for algorithm entry */
typedef int (*t_ssl_fptr)(t_ssl_command *command);

/* metadata for each algorithm */
typedef struct s_ssl_algo {
    char      *name;
    t_ssl_fptr      f;
    int       nb_options;
    const char      **options;
    const char      **options_long;
    const char      **args;
    const char      **descriptions;
    bool            noflag_as_file;
} t_ssl_algo;

extern t_ssl_algo g_ssl_algos[];

// hash/whirlpool.c
int whirlpool(t_ssl_command *command);

// hash/md5.c
int md5(t_ssl_command *command);

// hash/sha256.c
int sha256(t_ssl_command *command);

// cipher/base64.c
int base64(t_ssl_command *command);

// cipher/base64.c
int base64(t_ssl_command *command);

// cipher/des.c
int des(t_ssl_command *command);

// parse.c
int parse(int argc, char **argv, t_ssl_command *command);

// common.c

uint32_t    left_rotate(uint32_t value, int shift);

uint32_t    right_rotate(uint32_t value, int shift);

// free
void    free_command(t_ssl_command *command);

// utils

char    *read_fd(int fd, size_t *out_size);