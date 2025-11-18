# include "../include/ft_ssl.h"

char    *read_fd(int fd)
{
	char	buffer[4096];
    char    *result;
    size_t     bytes_read;

	result = ft_calloc(1, sizeof(char));
    if (!result)
        return (NULL);

    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0)
    {
        buffer[bytes_read] = '\0';
        char *tmp = ft_strjoin(result, buffer);
        if (!tmp)
        {
            free(result);
            ft_printf("ft_ssl: malloc error\n");
            return (NULL);
        }
        free(result);
        result = tmp;
    }
    return (result);
}