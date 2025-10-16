EXECUTABLE = ft_ssl
CC = gcc
CFLAGS = -Wall -Wextra -Werror
SRC_DIR = src
OBJ_DIR = .obj
INC_DIR = include
SRCS_LSRCS_LIST = main md5 sha256 preprocess common primes
IR = libft
LIBFT = libft/libft.a

SRCS = $(addprefix $(SRC_DIR)/, $(addsuffix .c, $(SRCS_LIST)))
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
INCS = -I$(INC_DIR) -I$(LIBFT_DIR)

all: $(EXECUTABLE)

$(EXECUTABLE): $(LIBFT) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lm -L$(LIBFT_DIR) -lft
	echo "Build complete: $(EXECUTABLE)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	echo "Compiling $<..."
	@mkdir -p $(OBJ_DIR)
	@$(CC) $(CFLAGS) $(INCS) -c $< -o $@ 

$(LIBFT): $(LIBFT_DIR)
	echo "Building libft..."
	@$(MAKE) -C $(LIBFT_DIR)

$(LIBFT_DIR):
	echo "Cloning libft submodule..."
	@git submodule update --init --recursive

clean:
	@$(MAKE) -C $(LIBFT_DIR) clean
	@rm -rf $(OBJ_DIR)

fclean: clean
	@$(MAKE) -C $(LIBFT_DIR) fclean
	@rm -f $(EXECUTABLE)

re: fclean all

.PHONY: all clean fclean re

