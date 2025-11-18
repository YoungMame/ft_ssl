#include "ft_ssl.h"

void    free_command(t_ssl_command *command)
{
    for (int i = 0; i < command->flag_count; i++)
    {
        t_ssl_flag flag = command->flags[i];
        if (flag.value)
            free(flag.value);

    }
    free(command->flags);

    for(size_t i = 0; i < command->message_count; i++)
    {
        if (command->messages[i].input)
        {
            free(command->messages[i].input);
            command->messages[i].input = NULL;
        }
        if (command->messages[i].content)
        {
            free(command->messages[i].content);
            command->messages[i].content = NULL;
        }
        if (command->messages[i].output)
        {
            free(command->messages[i].output);
            command->messages[i].output = NULL;
        }
    }
    free(command);
}

t_ssl_command   *init_command()
{
    t_ssl_command   *command;
    command = ft_calloc(1, sizeof(t_ssl_command));
    if (!command)
        return (NULL);
        
    command->flag_count = 0;
    command->message_count = 0;
    command->flags = NULL;
    command->mode = -1;
    ft_memset(command->messages, 0, sizeof(command->messages));
    return (command);
}

int main(int argc, char **argv)
{
    t_ssl_command   *command;

    // Input
    if (argc < 2) {
        ft_printf("Usage: ft_ssl <command> [options]\n");
        return (1);
    }
    
    command = init_command();
    if (command == NULL)
        return (free_command(command), 1);

    int success = parse(argc, argv, command);
    if (!success)
        return (1);

    g_ssl_algos[command->mode].f(command);
    
    return (free_command(command), 0);
}

