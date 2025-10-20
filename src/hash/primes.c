# include "ft_ssl.h"

bool    is_prime(int number)
{
    for (int i = 2; i < number; i++)
    {
        if (number % i == 0)
            return (false);
    }
    return (true);
}

int *generate_primes(int len)
{
    int     primes_counter = 0;
    int     i = 2;
    int     *array = NULL;
    int     *temp = NULL;

    if (len < 1)
        return (NULL);

    while (primes_counter < len)
    {
        if (is_prime(i))
        {
            temp = ft_calloc(primes_counter + 2, sizeof(int));
            if (temp == NULL)
                return (NULL);
            ft_memcpy(temp, array, sizeof(int) * primes_counter);
            free(array);
            array = temp;
            temp = NULL;
            array[primes_counter] = i;
            array[primes_counter + 1] = 0;
            primes_counter++;
        }
        i++;
    }
    return (array);
}