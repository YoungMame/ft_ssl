# include "ft_ssl.h"

int             base64_process_command_inputs(t_ssl_command *command)
{
    if (command->message_count == 0)
    {

        command->messages[command->message_count].input = ft_strdup("stdin");
        command->messages[command->message_count].type = SSL_INPUT_STDIN;
        command->messages[command->message_count].content = read_fd(STDIN_FILENO);
        command->message_count += 1;
        if (!command->messages[0].content)
            return (ft_printf("ft_ssl: Error: cannot read\n"), 0);
    }
    else
    {
        int fd = open(command->messages[0].input, O_RDONLY);
        if (fd < 0)
            return (ft_printf("ft_ssl: %s: No such file or directory\n", command->messages[0].input), 0);
        command->messages[0].content = read_fd(fd);
        close(fd);
        if (!command->messages[0].content)
            return (ft_printf("ft_ssl: Error: cannot read\n"), 0);
    }
    return (1);
}

t_base64_params   base64_process_command_flags(t_ssl_command *command)
{
    t_base64_params params;

    params.decode = false;
    params.output_fd = STDOUT_FILENO;

    for (int i = 0; i < command->flag_count; i++)
    {
        if (command->flags[i].index == 0)
            params.decode = true;
        else if (command->flags[i].index == 1)
            params.decode = false;
        else if (command->flags[i].index == 2 && command->flags[i].value && command->message_count == 0)
        {
            command->messages[command->message_count].input = ft_strdup(command->flags[i].value);
            command->messages[command->message_count].type = SSL_INPUT_FILE;
            command->message_count += 1;
        }
        else if (command->flags[i].index == 3)
        {
            printf("flag output file: %s\n", command->flags[i].value);
            params.output_fd = open(command->flags[i].value, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (params.output_fd < 0)
                return (ft_printf("ft_ssl: Error: %s: Cannot open output file\n", command->flags[i].value), params);
        }
    }
    return (params);
}

void    base64_output_messages(t_ssl_command *command, t_base64_params params, const char *algo_name)
{
    (void)algo_name;
    for (size_t i = 0; i < command->message_count; i++)
    {
        t_ssl_message   *message = &command->messages[i];

        ft_putstr_fd(message->output, params.output_fd);
        ft_putstr_fd("\n", params.output_fd);
    }
    return ;
}