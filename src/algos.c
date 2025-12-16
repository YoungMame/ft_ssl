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

static const char *base64_options[] = { "-d", "-e", "-i", "-o", NULL };
static const char *base64_options_long[] = { "-decode", "-encode", "-input", "-output", NULL };
static const char *base64_args[] = { NULL, NULL, "<file>", "<file>", NULL };
static const char *base64_descriptions[] = {
    "decode data from base64",
    "encode data to base64",
    "use <file> as input",
    "use <file> as output",
    NULL
};

static const char *des_options[] = { "-a", "-d", "-e", "-i", "-o", "-k", "-p", "-s", "-v", "-P", NULL };
static const char *des_options_long[] = { NULL, "--decode", "--encode", "--input", "--output", "--key", "--password", "--salt", "--initialization-vector", "--show-key", NULL };
static const char *des_args[] = { NULL, NULL, NULL, "<file>", "<file>", "<key>", "<password>", "<salt>", "<iv>", NULL, NULL };
static const char *des_descriptions[] = {
    "decode/encode the input/output in base64, depending on the encrypt mode",
    "decrypt mode",
    "encrypt mode (default)",
    "input file for message",
    "output file for message",
    "key in hex is the next argument",
    "the password in ASCII is the next argument",
    "the salt in hex is the next argument",
    "initialization vector in hex is the next argument",
    "print the key, iv and salt used",
    NULL
};

static const char *empty_array[] = {};

/* definition for the extern in the header — must be file-scope (not inside a function) */
t_ssl_algo g_ssl_algos[SSL_MODE_COUNT] = {
    {
        .name = "Message Digest commands:",
        .f = NULL,
        .nb_options = 0,
        .options = empty_array,
        .options_long = empty_array,
        .args = empty_array,
        .descriptions = empty_array,
        .noflag_as_file = false
    },
    {
        .name = "sha256",
        .f = sha256,
        .nb_options = 4,
        .options = hash_options,
        .options_long = hash_options_long,
        .args = hash_args,
        .descriptions = hash_descriptions,
        .noflag_as_file = true
    },
    {
        .name = "md5",
        .f = md5,
        .nb_options = 4,
        .options = hash_options,
        .options_long = hash_options_long,
        .args = hash_args,
        .descriptions = hash_descriptions,
        .noflag_as_file = true
    },
    {
        .name = "whirlpool",
        .f = whirlpool,
        .nb_options = 4,
        .options = hash_options,
        .options_long = hash_options_long,
        .args = hash_args,
        .descriptions = hash_descriptions,
        .noflag_as_file = true
    },
    {
        .name = "Cipher commands:",
        .f = NULL,
        .nb_options = 0,
        .options = empty_array,
        .options_long = empty_array,
        .args = empty_array,
        .descriptions = empty_array,
        .noflag_as_file = false
    },
    {
        .name = "base64",
        .f = base64,
        .nb_options = 4,
        .options = base64_options,
        .options_long = base64_options_long,
        .args = base64_args,
        .descriptions = base64_descriptions,
        .noflag_as_file = false
    },
    {
        .name = "des",
        .f = des,
        .nb_options = 10,
        .options = des_options,
        .options_long = des_options_long,
        .args = des_args,
        .descriptions = des_descriptions,
        .noflag_as_file = false
    },
    {
        .name = "des-ecb",
        .f = des,
        .nb_options = 10,
        .options = des_options,
        .options_long = des_options_long,
        .args = des_args,
        .descriptions = des_descriptions,
        .noflag_as_file = false
    },
    {
        .name = "des-cbc",
        .f = des,
        .nb_options = 10,
        .options = des_options,
        .options_long = des_options_long,
        .args = des_args,
        .descriptions = des_descriptions,
        .noflag_as_file = false
    },
    {
        .name = "3des",
        .f = des,
        .nb_options = 10,
        .options = des_options,
        .options_long = des_options_long,
        .args = des_args,
        .descriptions = des_descriptions,
        .noflag_as_file = false
    },
    {
        .name = "3des-cbc",
        .f = des,
        .nb_options = 10,
        .options = des_options,
        .options_long = des_options_long,
        .args = des_args,
        .descriptions = des_descriptions,
        .noflag_as_file = false
    },
    {
        .name = "3des-ecb",
        .f = des,
        .nb_options = 10,
        .options = des_options,
        .options_long = des_options_long,
        .args = des_args,
        .descriptions = des_descriptions,
        .noflag_as_file = false
    },
    {
        .name = "des-pcbc",
        .f = des,
        .nb_options = 10,
        .options = des_options,
        .options_long = des_options_long,
        .args = des_args,
        .descriptions = des_descriptions,
        .noflag_as_file = false
    },
    {
        .name = "3des-pcbc",
        .f = des,
        .nb_options = 10,
        .options = des_options,
        .options_long = des_options_long,
        .args = des_args,
        .descriptions = des_descriptions,
        .noflag_as_file = false
    },
};