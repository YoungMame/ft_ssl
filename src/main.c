#include "ft_ssl.h"

void    free_command(t_ssl_command *command)
{
    if (command->name)
    {
        free(command->name);
        command->name = NULL;
    }
    for (size_t i = 0; i < command->flag_count; i++)
    {
        t_ssl_flag flag = command->flags[i];
        if (flag.value)
            free(flag.value);

    }
    free(command->flags);

    for(size_t i = 0; i < command->messages_count; i++)
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
    command->messages_count = 0;
    command->flags = NULL;
    command->mod = -1;
    ft_memset()
    return (command);
}

int main(int argc, char **argv)
{
    t_ssl_command   *command;
    int             (*fptr)(t_ssl_command*);

    g_ssl_algos = init_algos();

    // Input
    if (argc < 2) {
        ft_printf("Usage: ft_ssl <command> [options]\n");
        return (1);
    }
    
    command = init_command();
    if (command == NULL)
        return (free_command(command), 1);

    command = parse(argv, argv, command);

    // TODO g_ssl_algos[command->mode].fptr(command);
    
    return (free_command(command), 0);
}

