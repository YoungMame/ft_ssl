#pragma once

# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <unistd.h>
# include <stdint.h>
# include <inttypes.h>

// md5_padding.c
char *get_padded_message(char *message, size_t *total_len);

// md5_main.c
char *md5(char *message);

