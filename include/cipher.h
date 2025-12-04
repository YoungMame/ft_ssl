# pragma once

typedef struct s_base64_params {
    bool    decode;
    int     output_fd;
}   t_base64_params;

typedef struct s_des_params {
    bool    decode;
    int     output_fd;
}   t_des_params;

typedef struct s_ssl_command t_ssl_command;

t_base64_params   base64_process_command_flags(t_ssl_command *command);

int             base64_process_command_inputs(t_ssl_command *command);

void            base64_output_messages(t_ssl_command *command, t_base64_params params, const char *algo_name);

t_des_params   des_process_command_flags(t_ssl_command *command);

int             des_process_command_inputs(t_ssl_command *command);

void            des_output_messages(t_ssl_command *command, t_des_params params, const char *algo_name);

extern const uint8_t DES_SBOX[8][4][16];

extern const uint8_t DES_IP[64];

extern const uint8_t DES_FP[64];

extern const uint8_t DES_EBOX[48];

extern const uint8_t DES_PBOX[32];

extern const uint8_t DES_PC1_LEFT[28];

extern const uint8_t DES_PC1_RIGHT[28];

extern const uint8_t DES_PC2[48];

extern const uint8_t DES_SHIFTS[16];