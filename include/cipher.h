# pragma once

typedef struct s_base64_params {
    bool    decode;
}   t_base64_params;

typedef struct s_ssl_command t_ssl_command;

t_base64_params   base64_process_command_flags(t_ssl_command *command);

int             base64_process_command_inputs(t_ssl_command *command, t_base64_params params);

void            ofutput_messages(t_ssl_command *command, t_base64_params params, const char *algo_name);