#include "ft_ssl.h"

static void realloc_flags(t_ssl_command *command)
{

}

static int add_flag(t_ssl_command *command, int index, char *value)
{
    t_ssl_flag  flag;
    t_ssl_flag  *new_flags;
    char    *t_value = NULL;
    if (value != NULL)
    {
        t_value = ft_strdup(value);
        if (!t_value)
            return (0); // TODO MALLOC ERROR
    }
    command->flag_count += 1;
    new_flags = ft_calloc(command->flag_count + 1, sizeof(t_ssl_flag));
    if (!new_flags)
        return ; // TODO handle malloc error
    for (int i = 0; i < command->flag_count; i++)
    {
        new_flags[i] = command->flags[i];
    }
    free(command->flags);
    command->flags = new_flags;
    flag.value = t_value;
    flag.index = index;
    command->flags[command->flag_count - 1] = flag;
    return (1);
}

int parse(int argc, char **argv, t_ssl_command *command)
{
    t_ssl_algo  algo;
    int         algo_index = -1;

    // printf("hello %s \n", hash_options[0]);

    for (int i = 0; i < SSL_MODE_COUNT; i++)
    {
        if (!ft_strncmp(argv[1], g_ssl_algos[i].name, ft_strlen(argv[1])))
        {
            algo_index = i;
            algo = g_ssl_algos[algo_index];
            command->mode = i;
            break ;
        }
    }
    if (algo_index == -1)
    {
        ft_printf("ft_ssl: Error: %s is an invalid command.\n", argv[1]);
        ft_printf("Available commands:\n");
        for (int i = 0; i < SSL_MODE_COUNT; i++)
        {
            printf("%s\n", g_ssl_algos[i].name);
        }
        return (free_command(command), 0);
    }

    for (int i = 2; i < argc; i++)
    {
        for (int j = 0; j < algo.nb_options; j++)
        {
            if (!ft_strncmp(argv[i], algo.options[j], ft_strlen(argv[i])) || (algo.options_long[j] && !(ft_strncmp(argv[i], algo.options_long[j], ft_strlen(argv[i])))))
            {
                if (algo.args[j] != NULL)
                {
                    if (i + 1 >= argc)
                        return (free_command(command), 0); // TODO handle missing option argument
                    i++;
                    if (!(add_flag(command, j, argv[i])))
                        return (free_command(command), 0);  // TODO handle malloc error
                }
                else
                {
                    if (!(add_flag(command, j, NULL)))
                        return (free_command(command), 0);  // TODO handle malloc error
                }
            }
        }
    }
    return (1);
}
