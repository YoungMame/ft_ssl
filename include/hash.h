typedef struct s_hash_params {
    bool    should_read_stdin;
    bool    is_quiet;
    bool    is_reversed;
}   t_hash_params;

t_hash_params   *process_command_flags(t_ssl_command *command);