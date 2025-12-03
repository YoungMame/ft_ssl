# include "ft_ssl.h"

int base64(t_ssl_command *command)
{
    t_base64_params params;

    params = base64_process_command_flags(command);
    if (params.output_fd < 0)
        return (0);
    if (!base64_process_command_inputs(command))
        return (0);
    ft_printf("Processing %zu message(s) with base64\n", command->message_count);
    base64_output_messages(command, params, "base64");
    if (params.output_fd != STDOUT_FILENO)
        close(params.output_fd);
    return (1);
}