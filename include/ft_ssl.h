#pragma once

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <stdint.h>
# include <inttypes.h>
# include <math.h>

// MD5 CONSTANTS
# define MD5_CHUNK_SIZE 512
# define MD5_INITIAL_A 0x67452301
# define MD5_INITIAL_B 0xEFCDAB89
# define MD5_INITIAL_C 0x98BADCFE
# define MD5_INITIAL_D 0x10325476
# define MD5_SHIFT_PER_ROUND { \
    {7, 12, 17, 22}, \
    {5,  9, 14, 20}, \
    {4, 11, 16, 23}, \
    {6, 10, 15, 21}  \
}

// md5_padding.c
char *get_preprocessed_message(char *message, size_t *total_len);

// md5_main.c
char *md5(char *message);

