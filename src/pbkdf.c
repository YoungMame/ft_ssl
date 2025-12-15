# include "ft_ssl.h"

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_LEN 32

// HMAC = h ( (K ^ opad) ∥ h( (K ^ ipad) ∥ message ) )
uint8_t *hmac_hash256(uint8_t *message, size_t message_len, uint8_t *key, size_t key_len)
{
    uint8_t *k = NULL;

    if (key_len > SHA256_BLOCK_SIZE) {
        k = (uint8_t *)sha256_hashing((char *)key, key_len, false);
        key_len = SHA256_DIGEST_LEN;
    }
    else {
        k = ft_calloc(SHA256_BLOCK_SIZE, sizeof(uint8_t));
        if (!k)
            return (ft_printf("ft_ssl: Error: Memory error\n"), NULL);
        ft_memcpy(k, key, key_len);
    }

    uint8_t *inner_key = ft_calloc(SHA256_BLOCK_SIZE, sizeof(uint8_t));
    uint8_t *outer_key = ft_calloc(SHA256_BLOCK_SIZE, sizeof(uint8_t));
    if (!inner_key || !outer_key)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), NULL);

    // xor keys with ipad and opad
    for (size_t i = 0; i < SHA256_BLOCK_SIZE; i++)
    {
        inner_key[i] = k[i] ^ 0x36;
        outer_key[i] = k[i] ^ 0x5c;
    }

    uint8_t *inner_message = (uint8_t *)mem_join((char *)inner_key, SHA256_BLOCK_SIZE, (char *)message, message_len);
    if (!inner_message)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), NULL);

    // hashing inner message
    uint8_t *inner_hash = (uint8_t *)sha256_hashing((char *)inner_message, SHA256_BLOCK_SIZE + message_len, false);
    if (!inner_hash)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), NULL);

    // creating outer message
    uint8_t *outer_message = (uint8_t *)mem_join((char *)outer_key, SHA256_BLOCK_SIZE, (char *)inner_hash, SHA256_DIGEST_LEN);
    if (!outer_message)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), free(inner_hash), NULL);

    // final HMAC
    uint8_t *hmac = (uint8_t *)sha256_hashing((char *)outer_message, SHA256_BLOCK_SIZE + SHA256_DIGEST_LEN, false);
    if (!hmac)
        return (ft_printf("ft_ssl: Error: Memory error\n"), free(k), free(inner_key), free(outer_key), free(inner_message), free(inner_hash), free(outer_message), NULL);

    free(k);
    free(inner_key);
    free(outer_key);
    free(inner_message);
    free(inner_hash);
    free(outer_message);
    printf("HMAC: ");
    for (size_t x = 0; x < SHA256_DIGEST_LEN; x++)
        printf("%02x", (uint8_t)hmac[x]);
    printf("\n");
    return hmac;
}

// static uint8_t *xor_blocks(uint8_t *src1, uint8_t *src2, size_t len)
// {
//     uint8_t *dest = ft_calloc(len, sizeof(uint8_t));
//     if (!dest)
//         return NULL;
//     for (size_t i = 0; i < len; i++)
//     {
//         dest[i] = src1[i] ^ src2[i];
//     }
//     return dest;
// }

// Return a derived key of length 8 bytes (64 bits)
// iterations is the expected output len in bytes
// hlen is the number of bytes the hash function outputs
uint8_t *pbkdf2(const char *password, size_t password_len, const char *salt, size_t salt_len, t_pbkdf2_prf hash_func, size_t hlen, size_t iter, size_t dklen)
{
    u_int8_t    *result = NULL;
    size_t      block_count = dklen / hlen + (dklen % hlen != 0);
    uint8_t     t[block_count][hlen];

    for (size_t i = 0; i < block_count; i++)
    {
        // U1 = PRF(Password, Salt+INT_32_BE(i))
        // Block counter starts at 1, not 0
        uint32_t    be_int = __builtin_bswap32((uint32_t)(i + 1));
        uint8_t     *hmac_key = (uint8_t *)mem_join((char *)salt, salt_len, (char *)&be_int, 4);
        printf("Salt: ");
        for (size_t x = 0; x < salt_len; x++)
            printf("%02x", (uint8_t)salt[x]);
        printf("\n");

        printf("be_int = 0x%08x\n", be_int);

        printf("hmac_key (%zu bytes): ", salt_len + 4);
        for (size_t x = 0; x < salt_len + 4; x++)
            printf("%02x", hmac_key[x]);
        printf("\n");

        if (!hmac_key)
            return (NULL);

        uint8_t     *u = hash_func(hmac_key, salt_len + 4, (uint8_t *)password, password_len);
        free(hmac_key);
        if (!u)
            return (NULL);

        // Init Ti = U1
        ft_memcpy(t[i], u, hlen);
        
        for (size_t j = 1; j < iter; j++)
        {
            uint8_t *prev_u = u;
            u = hash_func(prev_u, hlen, (uint8_t *)password, password_len);
            free(prev_u);
            if (!u)
                return (NULL);

            // Ti = u1 ^ u2 ^ ... ^ uiter
            for (size_t k = 0; k < hlen; k++)
                t[i][k] ^= u[k];
        }

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

    printf("resu;lt = ");
    for (size_t x = 0; x < block_count * hlen; x++)
        printf("%02x", (uint8_t)result[x]);
    printf("\n");

    ft_memcpy(dk, result, dklen);
    free(result);

    printf("Derived key = ");
    for (size_t x = 0; x < dklen; x++)
        printf("%02x", (uint8_t)dk[x]);
    printf("\n");


    return dk;
}

// ./ft_ssl des-ecb -i test/files/text -p passphrase42 -s 0C871EEA3AF7AAAA
// openssl des-ecb -pbkdf2 -iter 10000 -in test/files/text -k passphrase42 -S 0C871EEA3AF7AAAA -provider legacy -provider default -P