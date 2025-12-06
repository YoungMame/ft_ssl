# include "ft_ssl.h"

typedef char *(*t_pbkdf2_prf)(char *, size_t, char *, size_t);

static char *generate_ipad(size_t len) {
    char *ipad = ft_calloc(len, sizeof(char));
    if (!ipad)
        return NULL;
    for (size_t i = 0; i < len; i++)
        ipad[i] = 0x36;
    return ipad;
}

static unsigned char *generate_opad(size_t len) {
    unsigned char *opad = ft_calloc(len, sizeof(char));
    if (!opad)
        return NULL;
    for (size_t i = 0; i < len; i++)
        opad[i] = 0x5c;
    return opad;
}

static void *mem_join(const void *ptr1, size_t len1, const void *ptr2, size_t len2) {
    void *new_mem = ft_calloc(len1 + len2, sizeof(char));
    if (!new_mem)
        return NULL;
    ft_memcpy(new_mem, ptr1, len1);
    ft_memcpy((char *)new_mem + len1, ptr2, len2);
    return new_mem;
}

// HMAC = h ( (K ⊕ opad) ∥ h( (K ⊕ ipad) ∥ message ) )
char *hmac_hash256(const char *message, const char *key, const size_t message_len, const size_t key_len)
{
    const int BLOCK_SIZE = 64; // 512 bits for SHA256 block size
    char ipad[BLOCK_SIZE];
    char opad[BLOCK_SIZE];
    char *h = NULL;
    char *k = NULL;

    ft_memset(ipad, 0x36, BLOCK_SIZE);
    ft_memset(opad, 0x5c, BLOCK_SIZE);

    // If key is longer than block size, hash it first
    if (ft_strlen(key) > BLOCK_SIZE)
    {
        k = sha256_hashing(key, key_len);
        if (!k)
            return (ft_printf("ft_ssl: Error: Memory error\n"), NULL);
    }
    else
    {
        k = ft_calloc(BLOCK_SIZE, sizeof(char));
        if (!k)
            return (ft_printf("ft_ssl: Error: Memory error\n"), NULL);
        ft_memcpy(k, key, key_len);
    }
    char *inner_key = ft_calloc(BLOCK_SIZE, sizeof(char));
    char *outer_key = ft_calloc(BLOCK_SIZE, sizeof(char));
    if (!inner_key || !outer_key)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), NULL);
    for (size_t i = 0; i < BLOCK_SIZE; i++)
    {
        inner_key[i] = k[i] ^ ipad[i];
        outer_key[i] = k[i] ^ opad[i];
    }
    char *inner_message = mem_join(inner_key, BLOCK_SIZE, message, message_len);
    if (!inner_message)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), NULL);

    // hashing inner message
    char *inner_hash = sha256_hashing(inner_message, BLOCK_SIZE + message_len);
    if (!inner_hash)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), NULL);

    // 32 bytes for sha256 hash
    char *outer_message = mem_join(outer_key, BLOCK_SIZE, inner_hash, 32);
    if (!outer_message)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), free(inner_hash), NULL);

    // Final HMAC
    char *hmac = sha256_hashing(outer_message, BLOCK_SIZE + 32);
    if (!hmac)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), free(inner_hash), free(outer_message), NULL);
}

// Return a derived key of length 8 bytes (64 bits)
char *pbkdf2_8(const char *password, const char *salt, t_pbkdf2_prf hash_func, int iterations)
{
    // hmac_hash256(password, salt, ft_strlen(password), ft_strlen(salt));
    return ft_strdup("derived_key_placeholder");
}