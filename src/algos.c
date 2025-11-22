#include "ft_ssl.h"

static const char *hash_options[] = { "-p", "-q", "-r", "-s", NULL };
static const char *hash_options_long[] = { NULL, NULL, "--reverse", NULL, NULL };
static const char *hash_args[] = { NULL, NULL, NULL, "<string>", NULL };
static const char *hash_descriptions[] = {
    "echo STDIN to STDOUT and append the checksum to STDOUT",
    "quiet mode",
    "reverse the format of the output",
    "print the sum of the given string",
    NULL
};

/* definition for the extern in the header — must be file-scope (not inside a function) */
t_ssl_algo g_ssl_algos[SSL_MODE_COUNT] = {
    {
        .name = "sha256",
        .f = sha256,
        .nb_options = 4,
        .options = hash_options,
        .options_long = hash_options_long,
        .args = hash_args,
        .descriptions = hash_descriptions
    },
    {
        .name = "md5",
        .f = md5,
        .nb_options = 4,
        .options = hash_options,
        .options_long = hash_options_long,
        .args = hash_args,
        .descriptions = hash_descriptions
    },
    {
        .name = "whirlpool",
        .f = whirlpool,
        .nb_options = 4,
        .options = hash_options,
        .options_long = hash_options_long,
        .args = hash_args,
        .descriptions = hash_descriptions
    }
};