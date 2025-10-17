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