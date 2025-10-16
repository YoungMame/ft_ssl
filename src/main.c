#include "ft_ssl.h"

void    free_command(t_ssl_command *command)
{
    if (command->name)
    {
        free(command->name);
        command->name = NULL;
    }
    for(size_t i = command->messages_count; i < command->messages_count; i++)
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
}

// static void    free_message_content(t_ssl_message message)
// {
//     if (message.input)
//     {
//         free(message.input);
//         message.input = NULL;
//     }
//     if (message.content)
//     {
//         free(message.content);
//         message.content = NULL;
//     }
//     if (message.output)
//     {
//         free(message.output);
//         message.output = NULL;
//     }
// }

t_ssl_command   *init_command()
{
    t_ssl_command   *command;
    command = malloc(sizeof(t_ssl_command));
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

    if (!ft_strncmp(argv[1], "md5", ft_strlen(argv[1])))
    {
        fptr = &md5;
        command->name = ft_strdup("MD5");
    }
    else if (!ft_strncmp(argv[1], "sha256", ft_strlen(argv[1])))
    {
        fptr = &sha256;
        command->name = ft_strdup("SHA256");
    }
    else
    {
        ft_printf("ft_ssl: Error: %s is an invalid command.\n", argv[1]);
        ft_printf("Available commands:\n");
        ft_printf("md5\n");
        ft_printf("sha256\n");
        ft_printf("\n");
        ft_printf("flags:\n");
        ft_printf("-p -q -r -s\n");
        return (1);
    }

    for (int i = 2; i < argc; i++)
    {
        if (!ft_strncmp(argv[i], "-r", ft_strlen(argv[i])))
        {
            command->is_format_reversed = true;
        }
        else if (!ft_strncmp(argv[i], "-q", ft_strlen(argv[i])))
        {
            command->is_quiet = true;
        }
        else if (!ft_strncmp(argv[i], "-p", ft_strlen(argv[i])))
        {
            command->is_outputing_stdin = true;
        }
        else if (!ft_strncmp(argv[i], "-s", ft_strlen(argv[i])))
        {
            if (argc < i)
                return (free_command(command), 1);

            t_ssl_message   message;
            char            *input = ft_strdup(argv[i + 1]);
            message.type = SLL_INPUT_STRING;
            message.input = input;
            message.content = ft_strdup(input);
            command->messages[command->messages_count] = message;
            command->messages_count++;
            i++;
        }
        else
        {
            t_ssl_message   message;

            char    *input = ft_strdup(argv[i]);
            message.type = SLL_INPUT_FILE;
            message.input = input;
            message.content = NULL;
            char	*new_line;
            char    *content = ft_strdup("\0");
            int fd = open(input, O_RDONLY);
            if (fd < 0)
                return (free_command(command), 1);
            new_line = ft_get_next_line(fd);
            while (new_line)
            {
                content = ft_strjoin(content, new_line);
                free(new_line);
                new_line = ft_get_next_line(fd);
            }
            message.content = content;
            command->messages[command->messages_count] = message;
            command->messages_count++;
        }
    }

    // Read from stdin if no messages were added from arguments, or if -p flag is used
    if (command->messages_count == 0 || command->is_outputing_stdin)
    {
        char    *new_line;
        char    *content = ft_strdup("");
        if (content == NULL)
            return (free_command(command), 1);

        t_ssl_message   message;
        message.type = SLL_INPUT_STDIN;
        message.input = ft_strdup("(stdin)");
        message.content = NULL;
        
        new_line = ft_get_next_line(STDIN_FILENO);
        while (new_line)
        {
            if (command->is_outputing_stdin)
                ft_printf("%s", new_line); // Echo stdin when -p flag is used

            char *temp = ft_strjoin(content, new_line);
            free(content);
            content = temp;
            free(new_line);
            new_line = ft_get_next_line(STDIN_FILENO);
        }
        
        message.content = content;
        command->messages[command->messages_count] = message;
        command->messages_count++;
    }

    // Hashing
    for (size_t i = 0; i < command->messages_count; i++)
    {
        int success = fptr(argc, argv, command);    
        if (!success)
            return (free_command(command), 1);
    }

    // Output
    for (size_t i = 0; i < command->messages_count; i++)
    {
        if (!command->is_quiet)
        {
            if (command->is_format_reversed)
            {
                if (command->messages[i].type == SLL_INPUT_STRING)
                    ft_printf("%s \"%s\"\n", command->messages[i].output, command->messages[i].input);
                else if (command->messages[i].type == SLL_INPUT_STDIN && command->is_outputing_stdin)
                    ft_printf("(\"%s\")= %s\n", command->messages[i].content, command->messages[i].output);
                else if (command->messages[i].type == SLL_INPUT_STDIN)
                    ft_printf("%s\n", command->messages[i].output);
                else
                    ft_printf("%s %s\n", command->messages[i].output, command->messages[i].input);
            }
            else
            {
                if (command->messages[i].type == SLL_INPUT_STRING)
                    ft_printf("(\"%s\")= %s\n", command->messages[i].input, command->messages[i].output);
                else if (command->messages[i].type == SLL_INPUT_STDIN && command->is_outputing_stdin)
                    ft_printf("(\"%s\")= %s\n", command->messages[i].content, command->messages[i].output);
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

