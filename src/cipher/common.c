# include "ft_ssl.h"

int             base64_process_command_inputs(t_ssl_command *command, t_base64_params params)
{
    // If no inputs were provided, read from stdin
    if (command->message_count == 0 || params.should_read_stdin)
    {
        command->messages[command->message_count].type = SSL_INPUT_STDIN;
        command->messages[command->message_count].input = ft_strdup("stdin");
        if (!command->messages[command->message_count].input)
            return (ft_printf("Error: malloc failed\n"), 0);
        command->message_count += 1;
    }

    for (size_t i = 0; i < command->message_count; i++)
    {
        t_ssl_message   *message = &command->messages[i];

        if (message->type == SSL_INPUT_STDIN)
        {
            message->content = read_fd(STDIN_FILENO);
            if (!message->content)
                return (ft_printf("Error: cannot read\n"), 0);
        }
        else if (message->type == SSL_INPUT_FILE)
        {
            int fd = open(message->input, O_RDONLY);
            if (fd < 0)
                return (ft_printf("ft_ssl: %s: No such file or directory\n", message->input), 0);
            message->content = read_fd(fd);
            close(fd);
            if (!message->content)
                return (ft_printf("Error: cannot read\n"), 0);
        }
        else if (message->type == SSL_INPUT_STRING)
        {
            message->content = ft_strdup(message->input);
            if (!message->content)
                return (ft_printf("Error: malloc failed\n"), 0);
        }
    }
    return (1);
}

t_base64_params   base64_process_command_flags(t_ssl_command *command)
{
    t_base64_params params;

    params.decode = false;

    for (int i = 0; i < command->flag_count; i++)
    {
        if (command->flags[i].index == 0)
            params.should_read_stdin = true;
        else if (command->flags[i].index == 1)
            params.is_quiet = true;
        else if (command->flags[i].index == 2)
            params.is_reversed = true;
        else if (command->flags[i].index == 3)
        {
            command->messages[command->message_count].input = ft_strdup(command->flags[i].value);
            command->messages[command->message_count].type = SSL_INPUT_STRING;
            command->message_count += 1;
        }
    }
    return (params);
}

void    base64_output_messages(t_ssl_command *command, t_base64_params params, const char *algo_name)
{
    for (size_t i = 0; i < command->message_count; i++)
    {
        t_ssl_message   *message = &command->messages[i];

        if (params.is_quiet)
        {
            ft_printf("%s\n", message->output);
        }
        else if (params.is_reversed)
        {
            if (message->type == SSL_INPUT_STRING)
                ft_printf("%s %s\n", message->output, message->input);
            else if (message->type == SSL_INPUT_FILE)
                ft_printf("%s %s\n", message->output, message->input);
            else
            {
                if (params.should_read_stdin)
                    ft_printf("%s(%s)= %s\n", algo_name, message->content,message->output);
                else
                    ft_printf("%s(%s)= %s\n", algo_name, message->input, message->output);
            }
        }
        else
        {
            if (message->type == SSL_INPUT_STRING)
                ft_printf("%s(%s)= %s\n", algo_name, message->input, message->output);
            else if (message->type == SSL_INPUT_FILE)
                ft_printf("%s(%s)= %s\n", algo_name, message->input, message->output);
            else
            {
                if (params.should_read_stdin)
                    ft_printf("%s(%s)= %s\n", algo_name, message->content,message->output);
                else
                    ft_printf("%s(%s)= %s\n", algo_name, message->input, message->output);
            }
        }
    }
    return ;
}