#include "ft_ssl.h"

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
                    algo.args[j] = ft_strdup(argv[i]);
                }
                else
                {
                    // Handle flag options
                    if (!ft_strncmp(algo.options[j], "-p", ft_strlen(algo.options[j])))
                    {
                        command->is_outputing_stdin = true;
                    }
                    else if (!ft_strncmp(algo.options[j], "-q", ft_strlen(algo.options[j])))
                    {
                        command->is_quiet = true;
                    }
                    else if (!ft_strncmp(algo.options[j], "-r", ft_strlen(algo.options[j])) || !ft_strncmp(algo.options_long[j], "--reverse", ft_strlen(algo.options_long[j])))
                    {
                        command->is_format_reversed = true;
                    }
                }
            }
        }
        else if (!ft_strncmp(argv[i], "-s", ft_strlen(argv[i])))
        {
            if (argc < i)
                return (free_command(command), 1);

            t_ssl_message   message;
            char            *input = ft_strdup(argv[i + 1]);
            message.type = SSL_INPUT_STRING;
            message.input = input;
            message.content = ft_strdup(input);
            message.output = NULL;
            command->messages[command->messages_count] = message;
            command->messages_count++;
            i++;
        }
        else
        {
            t_ssl_message   message;

            char    *input = ft_strdup(argv[i]);
            message.type = SSL_INPUT_FILE;
            message.input = input;
            message.output = NULL;
            int fd = open(input, O_RDONLY);
            if (fd < 0)
            {
                ft_printf("ft_ssl: %s: No such file or directory\n", input);
                return (free_command(command), free(input), 1);
            }
            message.content = read_fd(fd);
            if (!message.content)
                return (free_command(command), 1);
            command->messages[command->messages_count] = message;
            command->messages_count++;
        }
    }

    // Read from stdin if no messages were added from arguments, or if -p flag is used
    if (command->messages_count == 0 || command->is_outputing_stdin)
    {
        t_ssl_message   message;
        message.type = SSL_INPUT_STDIN;
        message.input = ft_strdup("stdin");
        message.output = NULL;

        message.content = read_fd(STDIN_FILENO);
        if (!message.content)
            return (free_command(command), 1);
        command->messages[command->messages_count] = message;
        command->messages_count++;
    }

    // Hashing
    int success = fptr(argc, argv, command);    
    if (!success)
        return (NULL);
    return (command);
}
