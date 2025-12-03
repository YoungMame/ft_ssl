# include "ft_ssl.h"

int base64(t_ssl_command *command)
{
    t_base64_params   params = base64_process_command_flags(command);
    int             success = base64_process_command_inputs(command);
    if (!success)
        return (0);

    printf("Number of messages: %zu\n", command->message_count);

    for (size_t i = 0; i < command->message_count; i++)
    {
        char    *output = ft_strdup(command->messages[i].content);
        if (!output)
            return (0);
        command->messages[i].output = output;
        printf("Message %zu content: %s\n", i, command->messages[i].content);
    }

    printf("Outputting messages...\n");

    base64_output_messages(command, params, "base64");
     if (params.output_fd != STDOUT_FILENO)
        close(params.output_fd);
    
    return (1);
}