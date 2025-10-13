#include "ft_ssl.h"

int main(int argc, char **argv)
{
    char *hashed_message;

    hashed_message = NULL;
    if (argc != 3)
    {
        perror("Usage: ./ft_ssl <command> <string>\n");
        return (1);
    }


    if (!strcmp(argv[1], "md5"))
        hashed_message = md5(argv[2]);
    else
    {
        perror("Available algorithm are: [md5]\n");
        return (1);
    }

    
    printf("Hashed message = %s\n", hashed_message);
    return (0);
}