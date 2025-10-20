#include "ft_ssl.h"

static int add_flag(t_ssl_command *command, int index, char *value)
{
    t_ssl_flag  flag;
    char    *t_value = NULL;
    if (value != NULL)
    {
        t_value = ft_strdup(value);
        if (!t_value)
            return (0); // TODO MALLOC ERROR
    }
    flag.value = t_value;
    flag.index = index;
    command->flags[command->flag_count] = flag;
    return (1);
}

t_ssl_command   *parse(int argc, char **argv, t_ssl_command *command)
{
    t_ssl_algo  algo;
    int         algo_index = -1;

    for (int i = 0; i < SSL_MODE_COUNT; i++)
    {
        if (!ft_strncmp(argv[1], g_ssl_algos[i].name, ft_strlen(argv[1])))
        {
            algo_index = i;
            algo = g_ssl_algos[algo_index];
            command->mode = i;
            command->flags = ft_calloc(algo.nb_options + 1, sizeof(t_ssl_flag));
            if (!command->flags)
                return (free_command(command), 1); // TODO manage malloc error
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
        return (free_command(command), 1);
    }

    for (int i = 2; i < argc; i++)
    {
        for (int j = 0; j < algo.nb_options; j++)
        {
            if (!ft_strncmp(argv[i], algo.options[j], ft_strlen(argv[i])) || !ft_strncmp(argv[i], algo.options_long[j], ft_strlen(argv[i])))
            {
                if (algo.args[j] != NULL)
                {
                    if (i + 1 >= argc)
                        return (free_command(command), 1); // TODO handle missing option argument
                    i++;
                    if (!(add_flag(command, j, argv[i])))
                        return (free_command(command), 1);  // TODO handle malloc error
                }
                else
                {
                    if (!(add_flag(command, j, NULL)))
                        return (free_command(command), 1);  // TODO handle malloc error
                }
            }
        }
    }
    return (command);
}
