#include "ft_ssl.h"

static int add_flag(t_ssl_command *command, int index, char *value)
{
    t_ssl_flag  flag;
    t_ssl_flag  *new_flags;
    char    *t_value = NULL;
    if (value != NULL)
    {
        t_value = ft_strdup(value);
        if (!t_value)
            return (ft_printf("Error: malloc failed\n"), 0);
    }
    command->flag_count += 1;
    new_flags = ft_calloc(command->flag_count + 1, sizeof(t_ssl_flag));
    if (!new_flags)
        return (ft_printf("Error: malloc failed\n"), free(t_value), 0);
    for (int i = 0; i < command->flag_count - 1; i++)
    {
        new_flags[i] = command->flags[i];
    }
    new_flags[command->flag_count] = (t_ssl_flag){0, NULL};
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
        if (!ft_strncmp(argv[1], g_ssl_algos[i].name, ft_strlen(argv[1])) && g_ssl_algos[i].f != NULL)
        {
            algo_index = i;
            algo = g_ssl_algos[algo_index];
            command->mode = i;
            break ;
        }
    }
    if (algo_index == -1)
    {
        ft_printf("ft_ssl: Error: '%s' is an invalid command.\n\n", argv[1]);
        ft_printf("Available commands:\n\n");
        for (int i = 0; i < SSL_MODE_COUNT; i++)
        {
            ft_printf("%s\n", g_ssl_algos[i].name);
        }
        return (free_command(command), 0);
    }

    for (int i = 2; i < argc; i++)
    {
        bool    is_flag_spotted = false;
        for (int j = 0; j < algo.nb_options; j++)
        {
            if (!ft_strncmp(argv[i], algo.options[j], ft_strlen(argv[i])) || (algo.options_long[j] && !(ft_strncmp(argv[i], algo.options_long[j], ft_strlen(argv[i])))))
            {
                is_flag_spotted = true;
                if (algo.args[j] != NULL)
                {
                    if (i + 1 >= argc)
                        return (free_command(command), ft_printf("Error: missing option argument"), 0);
                    i++;
                    if (!(add_flag(command, j, argv[i])))
                        return (free_command(command), 0);
                }
                else
                {
                    if (!(add_flag(command, j, NULL)))
                        return (free_command(command), 0);
                }
                break ;
            }
        }
        if (!is_flag_spotted)
        {
            command->messages[command->message_count].input = ft_strdup(argv[i]);
            if (!command->messages[command->message_count].input)
                return (free_command(command), ft_printf("Error: malloc failed\n"), 0);
            command->messages[command->message_count].type = SSL_INPUT_FILE;
            command->message_count++;
        }
    }
    return (1);
}
