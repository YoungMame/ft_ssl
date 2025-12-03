# pragma once

typedef struct s_base64_params {
    bool    decode;
    int     output_fd;
}   t_base64_params;

typedef struct s_ssl_command t_ssl_command;

t_base64_params   base64_process_command_flags(t_ssl_command *command);

int             base64_process_command_inputs(t_ssl_command *command);

void            base64_output_messages(t_ssl_command *command, t_base64_params params, const char *algo_name);