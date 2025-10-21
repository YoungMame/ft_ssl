# pragma once

typedef struct s_hash_params {
    bool    should_read_stdin;
    bool    is_quiet;
    bool    is_reversed;
}   t_hash_params;

typedef struct s_ssl_command t_ssl_command;

t_hash_params   process_command_flags(t_ssl_command *command);

int             process_command_inputs(t_ssl_command *command, t_hash_params params);

void            output_messages(t_ssl_command *command, t_hash_params params, const char *algo_name);
