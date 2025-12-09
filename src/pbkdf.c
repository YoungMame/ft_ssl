# include "ft_ssl.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_LEN 32

// Wrapper pour adapter hmac_hash256 au type t_pbkdf2_prf
// t_pbkdf2_prf attend (key, key_len, message, message_len)
// hmac_hash256 prend (message, message_len, key, key_len)
char *hmac_sha256_prf(char *key, size_t key_len, char *message, size_t message_len)
{
    return hmac_hash256(message, key, message_len, key_len);
}

// HMAC = h ( (K ^ opad) ∥ h( (K ^ ipad) ∥ message ) )
char *hmac_hash256(const char *message, const char *key, const size_t message_len, size_t key_len)
{
    char ipad[SHA256_BLOCK_SIZE] = {0};
    char opad[SHA256_BLOCK_SIZE] = {0};
    char k0[SHA256_BLOCK_SIZE] = {0};
    // char *h = NULL;
    char *k = NULL;

    // generate ipad and opad
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }

    if (ft_strlen(key) > SHA256_BLOCK_SIZE) {
        k = sha256_hashing((char *)key, key_len); // returns 32 bytes
        key_len = SHA256_DIGEST_LEN; // <--- correction minimale
    }
    else
    {
        k = ft_calloc(SHA256_BLOCK_SIZE, sizeof(char));
        if (!k)
            return (ft_printf("ft_ssl: Error: Memory error\n"), NULL);
        ft_memcpy(k, key, key_len);
    }
    char *inner_key = ft_calloc(SHA256_BLOCK_SIZE, sizeof(char));
    char *outer_key = ft_calloc(SHA256_BLOCK_SIZE, sizeof(char));
    if (!inner_key || !outer_key)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), NULL);
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        inner_key[i] = k[i] ^ ipad[i];
        outer_key[i] = k[i] ^ opad[i];
    }
    char *inner_message = mem_join(inner_key, SHA256_BLOCK_SIZE, (char *)message, message_len);
    if (!inner_message)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), NULL);

    // hashing inner message
    char *inner_hash = sha256_hashing(inner_message, SHA256_BLOCK_SIZE + message_len);
    if (!inner_hash)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), NULL);

    // 32 bytes for sha256 hash
    char *outer_message = mem_join(outer_key, SHA256_BLOCK_SIZE, inner_hash, SHA256_DIGEST_LEN);
    if (!outer_message)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), free(inner_hash), NULL);

    // Final HMAC
    char *hmac = sha256_hashing(outer_message, SHA256_BLOCK_SIZE + SHA256_DIGEST_LEN);
    if (!hmac)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), free(inner_hash), free(outer_message), NULL);

    free(k);
    free(inner_key);
    free(outer_key);
    free(inner_message);
    free(inner_hash);
    free(outer_message);

    return hmac;
}

static uint8_t **init_blocks(size_t block_size, size_t count)
{
    uint8_t **blocks = ft_calloc(count + 1, sizeof(uint8_t *));
    if (!blocks)
        return NULL;
    for (size_t i = 0; i < count; i++)
    {
        blocks[i] = ft_calloc(block_size, sizeof(uint8_t));
        if (!blocks[i])
        {
            for (size_t j = 0; j < i; j++)
                free(blocks[j]);
            free(blocks);
            return NULL;
        }
    }
    blocks[count] = NULL;
    return blocks;
}

static void free_blocks(uint8_t **blocks)
{
    if (!blocks)
        return;
    for (size_t i = 0; blocks[i] != NULL; i++)
        free(blocks[i]);
    free(blocks);
}

static uint8_t *xor_blocks(uint8_t *src1, uint8_t *src2, size_t len)
{
    uint8_t *dest = ft_calloc(len, sizeof(uint8_t));
    if (!dest)
        return NULL;
    for (size_t i = 0; i < len; i++)
    {
        dest[i] = src1[i] ^ src2[i];
    }
    return dest;
}

// Per block function
static uint32_t pbkdf2_f4(const char *password, int password_len, uint8_t **t, int block_index, int block_size, int iterations, t_pbkdf2_prf hash_func)
{
    // t[0] = HMAC(password, salt || INT_32_BE(i))
    // Déjà fait avant l'appel
    
    for (int i = 1; i < iterations; i++)  // Commence à 1, pas 0
    {
        // U_i = HMAC(password, U_{i-1})
        char *hmac_result = hash_func((char *)password, password_len, (char *)t[block_index], block_size);
        if (!hmac_result)
            return -1;
            
        uint8_t *xor_result = xor_blocks(t[block_index], (uint8_t *)hmac_result, block_size);
        free(hmac_result);
        if (!xor_result)
            return -1;
            
        // Stocker U_i temporairement puis mettre à jour le résultat XOR cumulé
        ft_memcpy(t[block_index], xor_result, block_size);
        free(xor_result);
    }
    return 0;
}

// Return a derived key of length 8 bytes (64 bits)
// iterations is the expected output len in bytes
// hlen is the number of bytes the hash function outputs
char *pbkdf2_8(const char *password, const char *salt, t_pbkdf2_prf hash_func, int iterations, size_t hlen)
{
    int password_len = ft_strlen(password);
    int salt_len = ft_strlen(salt);
    int chunk_count = (8 + hlen - 1) / hlen; //
    char *result = NULL;

    uint8_t **t = init_blocks(hlen, chunk_count);
    if (!t)
        return (ft_printf("ft_ssl: Error: Memory error\n"), NULL);

    for (int i = 1; i < chunk_count; i++)
    {
        uint32_t block_index_be = __builtin_bswap32((uint32_t)i);
        char *concatened_salt = mem_join((char *)salt, salt_len, (void*)&block_index_be, 4);
        if (!concatened_salt)
            return (ft_printf("ft_ssl: Error: Memory error\n"), free_blocks(t), NULL);

        uint8_t *first_iteration = (uint8_t *)hash_func((char *)password, password_len, concatened_salt , salt_len + 4);
        free(concatened_salt);
        if (!first_iteration)
            return (NULL);

        ft_memcpy(t[i - 1], first_iteration, hlen);
        free(first_iteration);
        pbkdf2_f4((char *)password, password_len, t, i - 1, hlen, iterations, hash_func);
    }

    for (int i = 0; i < chunk_count; i++)
    {
        char *new_result = mem_join(result, i * hlen, (char *)t[i], hlen);
        if (!new_result)
            return (ft_printf("ft_ssl: Error: Memory error\n"), free_blocks(t), free(result), NULL);
        free(result);
        result = new_result;
    }
    free_blocks(t);

    return result;
}