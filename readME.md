# FT_SSL

## Hashing

### Introduction

A hashing algorithm is a one-way function that translates a text to a determined length hash.

#### Example use cases
- Storing passwords securely (combined with a salt to prevent rainbow table attacks)
- Verifying data integrity (checksums)
- Generating unique identifiers for data (hash tables)

#### Goals
- Cannot be possible to reverse the hash to get the original text
- Small changes in the input should produce a significantly different hash (avalanche effect)
- Quick calculation of the hash value
- Low number of collisions (different inputs producing the same hash)

### Algorithms implemented

#### MD5
- Produces a 128-bit hash value
- Broken by collisions for now
- Fast

##### Functioning

1. Pad the message so its length in bits + 64 is multiple of 512
2. Append the original length of the message (in bits) as a 64-bit integer
3. Initialize 4 buffers (A, B, C, D) with specific constants
4. Divide the message into 512-bit chunks
5. Process each chunk in 4 rounds of 16 operations using non-linear functions then add the result to the buffers

    5.1. The fours functions:

        Round 1, : F(X,Y,Z) = (X & Y) | (~X & Z) and g = j
        Round 2 : G(X,Y,Z) = (X & Z) | (Y & ~Z) and g := (5×i + 1) mod 16
        Round 3 : H(X,Y,Z) = X ^ Y ^ Z and g := (3×i + 5) mod 16
        Round 4 : I(X,Y,Z) = Y ^ (X | ~Z) and g := (7×i) mod 16

    5.2. For each of the 64 operations:

        temp = F result + a + constant K at i + words of the current chunk at g
        c become b
        d become c
        a become d
        left rotate temp of value corresponding to the current round in the shifts array and at it to b

    5.3. at the end of the chunk process, add each register to its buffer

6. Concatenate the 4 buffers of 32 bits to produce the final hash (128 bits)

#### SHA-256
- Produces a 256-bit hash value
- More secure than MD5
- Slower than MD5

##### Functioning
1. Pad the message so its length in bits + 64 is multiple of 512

2. Append the original length of the message (in bits) as a 64-bit integer

3. Initialize 8 buffers (A, B, C, D, E, F, G, H) with specific constants that are the first 32 bits of the fractional parts of the square roots of the first 8 prime numbers

4. Divide the message into 512-bit chunks

5 Definition of the functions:

    sigma0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)
    sigma1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
    choice(x, y, z) = (x AND y) XOR (NOT x AND z)
    majority(x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)
    SIGMA2(x) = ROTR^7(x) XOR ROTR^18(x) XOR SHR^3(x)
    SIGMA1(x) = ROTR^17(x) XOR ROTR^19(x) XOR SHR^10(x)

6. Process each chunk in 64 rounds
    6.1 Copy the first 16 words of the chunk into a message array of 64 words

    6.2 Extend the first 16 words into 48 other words using the formula: 

        W[i] = W[i] + sigma1(W[i - 15]) +W[i - 7] + sigma1(W[i - 2])
    
    6.3 Initialize the 8 working variables (a, b, c, d, e, f, g, h) with the current hash value

    6.4 Compression function main loop on the 64 words:

        temp1 = h + SIGMA1(e) + choice(e, f, g) + K[i] + W[i]
        temp2 = SIGMA0(a) + majority(a, b, c)
        h = g
        g = f
        f = e
        e = d + temp1
        d = c
        c = b
        b = a
        a = temp1 + temp2
    6.5 Add the compressed chunk to the current hash value:

        h0 += a

7. Concatenate the 8 buffers of 32 bits to produce the final hash (256 bits)

#### Whirlpool
- Produces a 512-bit hash value
- Slower than SHA-256

##### Functioning
1. Pad the message so its length in bits + 256 is multiple of 512
2. Append the original length of the message (in bits) as a 256-bit integer
3. Initialize the hash value with specific constants
4. Divide the message into 512-bit chunks
5. Process each chunk in 10 rounds
    5.1 Initialize the state matrix with the current hash value XORed with the current chunk
    5.2 For each of the 10 rounds:
        a. AddRoundKey: XOR the state matrix with the round key derived from the hash value
        b. SubBytes: Substitute each byte in the state matrix using a fixed S-box
        c. ShiftColumns: Cyclically shift the columns of the state matrix by different offsets
        d. MixRows: Mix the bytes in each row of the state matrix using a linear transformation
    5.3 Update the hash value by XORing it with the final state matrix
6. The final hash value is the concatenation of the 8 rows of the hash value matrix (512 bits)