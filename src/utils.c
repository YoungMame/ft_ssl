# include "../include/ft_ssl.h"

static char *mem_join(char *s1, size_t len1, char *s2, size_t len2)
{
    char *result;

    result = ft_calloc(len1 + len2 + 1, sizeof(char));
    if (!result)
        return (NULL);
    if (len1 > 0)
        ft_memcpy(result, s1, len1);
    if (len2 > 0)
        ft_memcpy(result + len1, s2, len2);
    return (result);
}

char    *read_fd(int fd, size_t *out_size)
{
	char	buffer[4096];
    char    *result;
    size_t     bytes_read;
    *out_size = 0;

	result = ft_calloc(1, sizeof(char));
    if (!result)
        return (NULL);

    while ((bytes_read = read(fd, buffer, 4096)) > 0)
    {
        char *tmp = mem_join(result, *out_size, buffer, bytes_read);
        if (!tmp)
        {
            free(result);
            ft_printf("ft_ssl: Error: malloc error\n");
            return (NULL);
        }
        free(result);
        result = tmp;
        *out_size += bytes_read;
    }
    return (result);
}