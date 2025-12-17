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
    int input_name_len = ft_strlen(argv[1]);
    for (int i = 0; i < SSL_MODE_COUNT; i++)
    {
        int algo_name_len = ft_strlen(g_ssl_algos[i].name);
        if (!ft_strncmp(argv[1], g_ssl_algos[i].name, (algo_name_len < input_name_len ? input_name_len : algo_name_len)) && g_ssl_algos[i].f != NULL)
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
        int arg_len = ft_strlen(argv[i]);

        for (int j = 0; j < algo.nb_options; j++)
        {
            int option_len = algo.options[j] ? ft_strlen(algo.options[j]) : 0;
            int option_long_len = algo.options_long[j] ? ft_strlen(algo.options_long[j]) : 0;

            if (!ft_strncmp(argv[i], algo.options[j], (arg_len > option_len ? arg_len : option_len)) || (algo.options_long[j] && !(ft_strncmp(argv[i], algo.options_long[j], (arg_len > option_long_len ? arg_len : option_long_len)))))            
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
            if (algo.noflag_as_file && argv[i][0] != '-')
            {
                command->messages[command->message_count].input = ft_strdup(argv[i]);
                if (!command->messages[command->message_count].input)
                    return (free_command(command), ft_printf("Error: malloc failed\n"), 0);
                command->messages[command->message_count].type = SSL_INPUT_FILE;
                command->message_count++;
            }
            else
            {
                ft_printf("ft_ssl: Error: '%s' is an invalid option.\n", argv[i]);
                for (int i = 0; i < algo.nb_options; i++)
                {
                    if (algo.options[i])
                        ft_printf("%s ", algo.options[i]);
                    if (algo.options_long[i])
                        ft_printf("%s ", algo.options_long[i]);
                    if (algo.args[i])
                        ft_printf("%s ", algo.args[i]);
                    if (algo.descriptions[i])
                        ft_printf(": %s", algo.descriptions[i]);
                    ft_printf("\n");
                }
                
                return (free_command(command), 0);
            }
        }
    }
    return (1);
}
