#include "ft_ssl.h"

void    init_algos()
{
    g_ssl_algos = {
        [SSL_MODE_SHA256] = {
            name = "sha256",
            f = sha256,
            nb_options = 4,
            options = (const char *[]){"-p", "-q", "-r", "-s", NULL},
            options_long = (const char *[]){NULL, NULL, "--reverse", NULL, NULL},
            args = (const char *[]){ NULL, NULL, NULL, "<string>", NULL },
            descriptions = (const char *[]){
                "echo STDIN to STDOUT and append the checksum to STDOUT",
                "quiet mode",
                "reverse the format of the output",
                "print the sum of the given string",
                NULL
            }
        },
        [SSL_MODE_MD5] = {
            name = "md5",
            f = md5,
            nb_options = 4,
            options = (const char *[]){"-p", "-q", "-r", "-s", NULL},
            options_long = (const char *[]){NULL, NULL, "--reverse", NULL, NULL},
            args = (const char *[]){ NULL, NULL, NULL, "<string>", NULL },
            descriptions = (const char *[]){
                "echo STDIN to STDOUT and append the checksum to STDOUT",
                "quiet mode",
                "reverse the format of the output",
                "print the sum of the given string",
                NULL
            }
        }
    };
}


