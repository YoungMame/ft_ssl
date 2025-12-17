EXECUTABLE = ft_ssl
CC = gcc
CFLAGS = -Wall -Wextra -Werror -g3
SRC_DIR = src
OBJ_DIR = .obj
INC_DIR = include
SRCS_LIST = main common utils algos pbkdf parsing/parse hash/common hash/md5 hash/sha256 hash/whirlpool hash/const_whirlpool hash/preprocess hash/primes \
			cipher/common cipher/base64 cipher/des cipher/const_des
LIBFT_DIR = libft
LIBFT = libft/libft.a

SRCS = $(addprefix $(SRC_DIR)/, $(addsuffix .c, $(SRCS_LIST)))
OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
INCS = -I$(INC_DIR) -I$(LIBFT_DIR)

OS = $(shell uname)
ifeq ($(OS), Darwin)
	CFLAGS += -fsanitize=address,undefined -g
	CC = clang
endif

all: $(EXECUTABLE)

$(EXECUTABLE): $(LIBFT) $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lm -L$(LIBFT_DIR) -lft
	echo "Build complete: $(EXECUTABLE)"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	echo "Compiling $<..."
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(dir $@)
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

test: all
	python3 test/des_pcbc_test.py
	python3 test/md5_test.py
	python3 test/sha256_test.py
	python3 test/base64_test.py
	python3 test/des_ecb_test.py
	python3 test/des_cbc_test.py
	python3 test/des3_cbc_test.py
	python3 test/des3_ecb_test.py
	python3 test/des3_pcbc_test.py

.PHONY: all clean fclean re test

