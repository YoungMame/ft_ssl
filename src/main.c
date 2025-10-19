#include "ft_ssl.h"

void    free_command(t_ssl_command *command)
{
    if (command->name)
    {
        free(command->name);
        command->name = NULL;
    }
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
        
    ft_memset(command, 0, sizeof(t_ssl_command));
    command->messages_count = 0;
    command->is_format_reversed = false;
    command->is_outputing_stdin = false;
    command->is_quiet = false;
    command->messages_count = 0;
    command->name = NULL;
    return (command);
}

int main(int argc, char **argv)
{
    t_ssl_command   *command;
    int             (*fptr)(int, char**, t_ssl_command*);

    // Input
    if (argc < 2) {
        ft_printf("Usage: ft_ssl <command> [options]\n");
        return (1);
    }
    
    command = init_command();
    if (command == NULL)
        return (free_command(command), 1);


    // Output
    for (size_t i = 0; i < command->messages_count; i++)
    {
        if (!command->is_quiet)
        {
            if (command->is_format_reversed)
            {
                if (command->messages[i].type == SSL_INPUT_STRING)
                    ft_printf("%s \"%s\"\n", command->messages[i].output, command->messages[i].input);
                else if (command->messages[i].type == SSL_INPUT_STDIN && command->is_outputing_stdin)
                    ft_printf("(\"%s\")= %s\n", command->messages[i].content, command->messages[i].output);
                else if (command->messages[i].type == SSL_INPUT_STDIN)
                    ft_printf("(\"%s\")= %s\n", command->messages[i].input, command->messages[i].output);
                else
                    ft_printf("%s %s\n", command->messages[i].output, command->messages[i].input);
            }
            else
            {
                if ((command->messages[i].type == SSL_INPUT_STDIN && command->is_outputing_stdin) || command->messages[i].type == SSL_INPUT_STRING)
                    ft_printf("%s(\"%s\")= %s\n", command->name, command->messages[i].content, command->messages[i].output);
                else
                    ft_printf("%s(%s)= %s\n", command->name, command->messages[i].input, command->messages[i].output);
            }
        }
        else
        {
            ft_printf("%s\n", command->messages[i].output);
        }
    }
    
    return (free_command(command), 0);
}

