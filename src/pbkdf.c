# include "ft_ssl.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_LEN 32

// HMAC = h ( (K ^ opad) ∥ h( (K ^ ipad) ∥ message ) )
char *hmac_hash256(char *message, size_t message_len, char *key, size_t key_len)
{
    char ipad[SHA256_BLOCK_SIZE] = {0};
    char opad[SHA256_BLOCK_SIZE] = {0};
    char *k = NULL;

    if (key_len > SHA256_BLOCK_SIZE) {
        k = sha256_hashing((char *)key, key_len);
        key_len = SHA256_DIGEST_LEN;
    }
    else {
        k = ft_calloc(SHA256_BLOCK_SIZE, sizeof(char));
        if (!k)
            return (ft_printf("ft_ssl: Error: Memory error\n"), NULL);
        ft_memcpy(k, key, key_len);
    }
    
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
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

    // creating outer message
    char *outer_message = mem_join(outer_key, SHA256_BLOCK_SIZE, inner_hash, SHA256_DIGEST_LEN);
    if (!outer_message)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), free(inner_hash), NULL);

    // final HMAC
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


// Return a derived key of length 8 bytes (64 bits)
// iterations is the expected output len in bytes
// hlen is the number of bytes the hash function outputs
uint8_t *pbkdf2(const char *password, size_t password_len, const char *salt, size_t salt_len, t_pbkdf2_prf hash_func, size_t hlen, size_t iter, size_t dklen)
{
    u_int8_t    *result = NULL;
    size_t      block_count = dklen / hlen + (dklen % hlen != 0);
    uint8_t     t[hlen][block_count];

    for (size_t i = 0; i < block_count; i++)
    {
        // U1 = PRF(Password, Salt+INT_32_BE(i))
        uint32_t    be_int = __builtin_bswap32((uint32_t)i);
        uint8_t     *hmac_key = (uint8_t *)mem_join((char *)salt, salt_len, (char *)&be_int, 4);
        if (!hmac_key)
            return (NULL);

        uint8_t     *u = (uint8_t *)hash_func((char *)password, password_len, (char *)hmac_key, salt_len + 4);

        free(hmac_key);
        if (!u)
            return (NULL);

        ft_memset(t[i], 0, hlen);

        printf("U_1[%zu] = ", i);
        for (size_t x = 0; x < hlen; x++)
            printf("%02x", u[x]);
        printf("\n");
        
        // Uc = PRF(Password, Uc-1)
        for (size_t j = 1; j < iter; j++)
        {
            uint8_t *prev_u = u;
            u = (uint8_t *)hash_func((char *)password, password_len, (char *)prev_u, salt_len + 4);
            if (!u)
                return (free(prev_u), NULL);

            uint8_t *tmp_u = u;
            u = xor_blocks(tmp_u, prev_u, hlen);
            if (!u)
                return (free(prev_u), free(tmp_u), NULL);

            free(prev_u);
            free(tmp_u);
        }
        // for (size_t x = 0; x < dklen; x++)
        //     printf("%02x", u[x]);
        // printf("\n");
        ft_memcpy(t[i], u, hlen);
        free(u);
    }
    // DK = T1 + T2 +....+ TdkLen/hlen

    result = ft_calloc(hlen + 1, sizeof(uint8_t));
    if (!result)
        return (NULL);

    ft_memcpy(result, t[0], hlen);

    // concatenate blocks
    for (size_t i = 1; i < block_count; i++)
    {
        size_t current_len = i * hlen;
        uint8_t *new_result = (uint8_t *)mem_join((char *)result, current_len, (char *)t[i], hlen);
        free(result);
        if (!new_result)
            return (NULL);

        result = new_result;
    }

    // extract right length
    uint8_t *dk = ft_calloc(dklen + 1, sizeof(uint8_t));
    if (!dk)
        return (free(result), NULL);

    ft_memcpy(dk, result, dklen);
    free(result);

    // printf("Derived key = ");
    // for (size_t x = 0; x < dklen; x++)
    //     printf("%02x", (uint8_t)dk[x]);
    // printf("\n");

    return dk;
}

// ./ft_ssl des-ecb -i test/files/text -p passphrase42 -s 0C871EEA3AF7AAAA
// openssl des-ecb -pbkdf2 -iter 10000 -in test/files/text -k passphrase42 -S 0C871EEA3AF7AAAA -provider legacy -provider default -P