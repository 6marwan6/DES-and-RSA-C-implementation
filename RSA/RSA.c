#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

//some helper functions




/* Functions to be implemented later */
void mode_keygen(const char *pub, const char *priv);
void mode_encrypt(const char *pub, const char *pt, const char *ct);
void mode_decrypt(const char *priv, const char *ct, const char *pt);





//Extended Euclidean Algorithm for modular inverse
static uint32_t mod_inverse(uint32_t a, uint64_t m)
{
    int64_t m0 = m, t, q;
    int64_t x0 = 0, x1 = 1;
    
    if (m == 1) return 0;
    
    int64_t a_signed = (int64_t)a;
    
    while (a_signed > 1) {
        q = a_signed / m0;
        t = m0;
        m0 = a_signed % m0;
        a_signed = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    
    if (x1 < 0) x1 += m;
    
    return (uint32_t)x1;
}

//compute N^(-1) mod R where R = 2^32//
static uint32_t compute_invN(uint32_t N)
{
    return mod_inverse(N, 1ULL << 32);
}

//Compute R^2 mod N where R = 2^32//
static uint32_t compute_R2modN(uint32_t N)
{
    uint64_t R2 = 1;
    for (int i = 0; i < 64; i++) {
        R2 = (R2 << 1) % N;
    }
    
    return (uint32_t)R2;
}

// MONTGOMERY MULTIPLICATION CORE//

/**
 * @param x     - Input value (up to 64 bits)
 * @param N     - Modulus
 * @param invN  - N^(-1) mod R, precomputed
 * @return      - x * R^(-1) mod N
 */
static inline uint32_t mont_redc(uint64_t x, uint32_t N, uint32_t invN)
{
    uint64_t t1 = x;
    uint64_t t2 = (uint64_t)((uint32_t)x * invN) * N;
    
    uint32_t res = (uint32_t)((t1 - t2) >> 32);
    res += N & -(t1 < t2);
    
    return res;
}

// Montgomery Multiplication
 
static inline uint32_t mont_mul(uint32_t a, uint32_t b,
                                uint32_t N, uint32_t invN)
{
    return mont_redc((uint64_t)a * b, N, invN);
}

//Convert to Montgomery Space//
static inline uint32_t to_mont(uint32_t a, uint32_t R2modN,
                               uint32_t N, uint32_t invN)
{
    return mont_redc((uint64_t)a * R2modN, N, invN);
}

//Convert from Montgomery Space

static inline uint32_t from_mont(uint32_t aR,
                                 uint32_t N, uint32_t invN)
{
    return mont_redc((uint64_t)aR, N, invN);
}


/**
 * RSA Modular Exponentiation 
 * @param value  - Base value (plaintext or ciphertext)
 * @param exp    - Exponent (public or private key)
 * @param N      - Modulus
 * @param invN   - N^(-1) mod R, precomputed
 * @param R2modN - R^2 mod N, precomputed
 * @return       - value^exp mod N
 */

uint32_t rsa_modexp(uint32_t value, uint32_t exp,
                    uint32_t N, uint32_t invN, uint32_t R2modN)
{

    uint32_t valueM = to_mont(value, R2modN, N, invN);
    

    uint32_t resultM = to_mont(1, R2modN, N, invN);

    while (exp > 0) {

        if (exp & 1)
            resultM = mont_mul(resultM, valueM, N, invN);
        
        valueM = mont_mul(valueM, valueM, N, invN);
        

        exp >>= 1;
    }

    return from_mont(resultM, N, invN);
}





static void check_file_exists(const char *fname)
{
    FILE *f = fopen(fname, "r");
    if (!f) {
        perror(fname);
        exit(1);
    }
    fclose(f);
}




int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "  %s g public_key.txt private_key.txt\n"
            "  %s e public_key.txt plaintext.txt ciphertext.txt\n"
            "  %s d private_key.txt ciphertext.txt plaintext.txt\n",
            argv[0], argv[0], argv[0]);
        return 1;
    }

    char mode = argv[1][0];

    switch (mode) {

    case 'g':   //// Key generation 
        if (argc != 4) {
            fprintf(stderr, "Error: invalid arguments for key generation\n");
            return 1;
        }
        mode_keygen(argv[2], argv[3]);
        break;

    case 'e':   //// Encryption 
        if (argc != 5) {
            fprintf(stderr, "Error: invalid arguments for encryption\n");
            return 1;
        }
        check_file_exists(argv[2]); // public key 
        check_file_exists(argv[3]); // plaintext 
        mode_encrypt(argv[2], argv[3], argv[4]);
        break;

    case 'd':    //// Decryption 
        if (argc != 5) {
            fprintf(stderr, "Error: invalid arguments for decryption\n");
            return 1;
        }
        check_file_exists(argv[2]); // private key 
        check_file_exists(argv[3]); // ciphertext 
        mode_decrypt(argv[2], argv[3], argv[4]);
        break;

    default:
        fprintf(stderr, "Error: unknown mode '%c' (use g, e, or d)\n", mode);
        return 1;
    }

    return 0;
}