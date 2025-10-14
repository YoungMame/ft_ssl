#include "ft_ssl.h"

int main(int argc, char **argv)
{
    t_ssl_command   *command;
    int             (*fptr)(int, char**, t_ssl_command*);

    // Input
    if (argc < 2) {
        printf("Usage: ft_ssl <command> [options]\n");
        return (1);
    }
    
    command = malloc(sizeof(t_ssl_command));
    if (!command)
        return (1); // TODO free all and exit
        
    // Initialize command structure
    memset(command, 0, sizeof(t_ssl_command));
    command->messages_count = 0;
    command->is_format_reversed = false;
    command->is_outputing_stdin = false;
    command->is_quiet = false;
    
    if (!strcmp(argv[1], "md5"))
    {
        fptr = &md5;
        command->name = ft_strdup("MD5");
    }
    else
    {
        printf("ft_ssl: Error: %s is an invalid command.\n", argv[1]);
        printf("Available commands:\n");
        printf("md5\n");
        printf("sha256\n");
        printf("\n");
        printf("flags:\n");
        printf("-p -q -r -s\n");
        return (1);
    }

    for (int i = 1; i < argc; i++)
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
            if (argc < i || !ft_strlen(argv[i + 1]))
                return (1); // TODO non existing file

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
                return (1); // TODO exit and free missing file
            new_line = ft_get_next_line(fd);
            while (new_line)
            {
                content = ft_strjoin(content, new_line);
                printf("first line%s", new_line);
                free(new_line);
                new_line = ft_get_next_line(fd);
            }
            message.content = content;
            command->messages[command->messages_count] = message;
            command->messages_count++;
        }
    }

    if (command->is_outputing_stdin) {
    	char	*new_line;
    	new_line = ft_get_next_line(STDIN_FILENO);
        printf("after new line");
    	while (new_line)
    	{
    		printf("first line%s", new_line);
    		free(new_line);
    		new_line = ft_get_next_line(STDIN_FILENO);
    	}
    	printf("\nwe printed all lines\n");
    	free(new_line);
    }

    // Hashing
    for (size_t i = 0; i < command->messages_count; i++)
    {
        int success = fptr(argc, argv, command);    
        if (!success)
            return (0); // TODO exit and free
        ft_printf("%s\n", command->messages[i].output);
    }

    // Output
    for (size_t i = 0; i < command->messages_count; i++)
    {
        if (command->is_outputing_stdin)
        {
            if (command->messages[i].type == SLL_INPUT_STDIN)
                ft_printf("%s\n", command->messages[i].content);
        }
        if (!command->is_quiet)
        {
            if (command->is_format_reversed)
                ft_printf("%s %s\n", command->messages[i].output, command->messages[i].input);
            else
            {
                ft_printf("(%s) = %s\n", command->messages[i].input, command->messages[i].output);
            }
        }
        else
        {
            ft_printf("%s\n", command->messages[i].output);
        }

    }
    
    return (0);
}

