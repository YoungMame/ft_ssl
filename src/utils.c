# include "../include/ft_ssl.h"

int ft_pow(int number, int pow)
{
    int result = 1;
    for (int i = 0; i < pow; i++)
    {
        result = result * number;
    }
    return (result);
}

double ft_fabs(double number)
{
    if (number < 0)
        return (-number);
    else
        return (number);
}

char    *read_fd(int fd)
{
	char	buffer[4096];
    char    *result;
    size_t     bytes_read;
    size_t	total_size = 0;

	result = malloc(0);
	if (!result)
	{
		ft_printf("ft_ssl: malloc error\n");
		return (NULL);
	}

    while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0)
    {
        char *temp = malloc(total_size + bytes_read);
        if (!temp)
        {
            free(result);
            ft_printf("ft_ssl: malloc error\n");
            return (NULL);
        }
        char *tmp = ft_strjoin(result, buffer);
        if (!tmp)
        {
            free(result);
            ft_printf("ft_ssl: malloc error\n");
            return (NULL);
        }
        free(result);
        result = tmp;
        total_size += bytes_read;
    }
    return (result);
}