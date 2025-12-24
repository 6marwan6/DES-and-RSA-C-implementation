#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static uint16_t generate_prime_16bit(void);
static uint32_t compute_invN(uint32_t N);
static uint32_t compute_R2modN(uint32_t N);
uint32_t rsa_modexp(uint32_t value, uint32_t exp, uint32_t N, uint32_t invN, uint32_t R2modN);

// Encryption: read (e, N) from public key, read plaintext, compute C = P^e mod N
void mode_encrypt(const char *pub, const char *pt, const char *ct)
{
    FILE *pub_file = fopen(pub, "r");
    if (!pub_file) {
        perror(pub);
        exit(1);
    }
    
    uint32_t e, N;
    if (fscanf(pub_file, "%X %X", &e, &N) != 2) {
        fprintf(stderr, "Error: invalid public key format\n");
        fclose(pub_file);
        exit(1);
    }
    fclose(pub_file);
    
    // Read plaintext
    FILE *pt_file = fopen(pt, "r");
    if (!pt_file) {
        perror(pt);
        exit(1);
    }
    
    uint32_t plaintext;
    if (fscanf(pt_file, "%X", &plaintext) != 1) {
        fprintf(stderr, "Error: invalid plaintext format\n");
        fclose(pt_file);
        exit(1);
    }
    fclose(pt_file);
    
    // Validate plaintext < N
    if (plaintext >= N) {
        fprintf(stderr, "Error: plaintext must be less than N\n");
        exit(1);
    }
    
    // Precompute Montgomery parameters
    uint32_t invN = compute_invN(N);
    uint32_t R2modN = compute_R2modN(N);
    
    // Encrypt: C = P^e mod N
    uint32_t ciphertext = rsa_modexp(plaintext, e, N, invN, R2modN);
    
    // Write ciphertext
    FILE *ct_file = fopen(ct, "w");
    if (!ct_file) {
        perror(ct);
        exit(1);
    }
    fprintf(ct_file, "%08X\n", ciphertext);
    fclose(ct_file);
    
    printf("Encryption complete: P=%08X -> C=%08X\n", plaintext, ciphertext);
}

// Decryption: read (d, N) from private key, read ciphertext, compute P = C^d mod N
void mode_decrypt(const char *priv, const char *ct, const char *pt)
{
    FILE *priv_file = fopen(priv, "r");
    if (!priv_file) {
        perror(priv);
        exit(1);
    }
    
    uint32_t d, N;
    if (fscanf(priv_file, "%X %X", &d, &N) != 2) {
        fprintf(stderr, "Error: invalid private key format\n");
        fclose(priv_file);
        exit(1);
    }
    fclose(priv_file);
    
    // Read ciphertext
    FILE *ct_file = fopen(ct, "r");
    if (!ct_file) {
        perror(ct);
        exit(1);
    }
    
    uint32_t ciphertext;
    if (fscanf(ct_file, "%X", &ciphertext) != 1) {
        fprintf(stderr, "Error: invalid ciphertext format\n");
        fclose(ct_file);
        exit(1);
    }
    fclose(ct_file);
    
    // Validate ciphertext < N
    if (ciphertext >= N) {
        fprintf(stderr, "Error: ciphertext must be less than N\n");
        exit(1);
    }
    
    // Precompute Montgomery parameters
    uint32_t invN = compute_invN(N);
    uint32_t R2modN = compute_R2modN(N);
    
    // Decrypt: P = C^d mod N
    uint32_t plaintext = rsa_modexp(ciphertext, d, N, invN, R2modN);
    
    // Write plaintext
    FILE *pt_file = fopen(pt, "w");
    if (!pt_file) {
        perror(pt);
        exit(1);
    }
    fprintf(pt_file, "%08X\n", plaintext);
    fclose(pt_file);
    
    printf("Decryption complete: C=%08X -> P=%08X\n", ciphertext, plaintext);
}


// Compute GCD for checking coprimality
static uint32_t gcd(uint32_t a, uint32_t b)
{
    while (b != 0) {
        uint32_t t = b;
        b = a % b;
        a = t;
    }
    return a;
}

// Extended Euclidean Algorithm for modular inverse (64-bit version for phi)
static uint32_t mod_inverse_64(uint32_t a, uint64_t m)
{
    int64_t m0 = (int64_t)m, t, q;
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
    
    if (x1 < 0) x1 += (int64_t)m;
    
    return (uint32_t)x1;
}

// Key generation: generate p, q, compute N, phi(N), e, d
void mode_keygen(const char *pub, const char *priv)
{
    srand((unsigned int)time(NULL));
    
    // Generate two distinct 16-bit primes
    uint16_t p = generate_prime_16bit();
    uint16_t q;
    do {
        q = generate_prime_16bit();
    } while (q == p);
    
    // Compute N = p * q (fits in 32 bits)
    uint32_t N = (uint32_t)p * (uint32_t)q;
    
    // Compute phi(N) = (p-1) * (q-1)
    uint64_t phi_N = (uint64_t)(p - 1) * (uint64_t)(q - 1);
    
    // Choose e: common choice is 65537, but if phi_N is small, use smaller e
    // e must be coprime with phi_N
    uint32_t e = 65537;
    if (e >= phi_N) {
        e = 257;
    }
    while (gcd(e, (uint32_t)phi_N) != 1) {
        e += 2;
    }
    
    // Compute d = e^(-1) mod phi(N)
    uint32_t d = mod_inverse_64(e, phi_N);
    
    // Write public key (e, N) to file
    FILE *pub_file = fopen(pub, "w");
    if (!pub_file) {
        perror(pub);
        exit(1);
    }
    fprintf(pub_file, "%08X %08X\n", e, N);
    fclose(pub_file);
    
    // Write private key (d, N) to file
    FILE *priv_file = fopen(priv, "w");
    if (!priv_file) {
        perror(priv);
        exit(1);
    }
    fprintf(priv_file, "%08X %08X\n", d, N);
    fclose(priv_file);
    
    printf("Key generation complete.\n");
    printf("p = %u, q = %u\n", p, q);
    printf("N = %08X\n", N);
    printf("phi(N) = %lu\n", (unsigned long)phi_N);
    printf("e = %08X\n", e);
    printf("d = %08X\n", d);
}





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

// Simple modular exponentiation for Miller-Rabin (without Montgomery)
static uint32_t mod_pow(uint32_t base, uint32_t exp, uint32_t mod)
{
    uint64_t result = 1;
    uint64_t b = base % mod;
    
    while (exp > 0) {
        if (exp & 1)
            result = (result * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    
    return (uint32_t)result;
}

// Miller-Rabin primality test
// Returns 1 if n is probably prime, 0 if composite
static int miller_rabin(uint32_t n, int k)
{
    if (n < 2) return 0;
    if (n == 2 || n == 3) return 1;
    if (n % 2 == 0) return 0;
    
    // Write n-1 as 2^r * d
    uint32_t d = n - 1;
    int r = 0;
    while ((d & 1) == 0) {
        d >>= 1;
        r++;
    }
    
    // Witness loop
    for (int i = 0; i < k; i++) {
        // Pick random a in [2, n-2]
        uint32_t a = 2 + rand() % (n - 3);
        
        uint32_t x = mod_pow(a, d, n);
        
        if (x == 1 || x == n - 1)
            continue;
        
        int composite = 1;
        for (int j = 0; j < r - 1; j++) {
            x = (uint32_t)(((uint64_t)x * x) % n);
            if (x == n - 1) {
                composite = 0;
                break;
            }
        }
        
        if (composite)
            return 0;
    }
    
    return 1;
}

// Generate a random 16-bit prime
static uint16_t generate_prime_16bit(void)
{
    uint16_t candidate;
    
    do {
        // Generate random odd number in range [32768, 65535] (15-16 bits)
        candidate = (uint16_t)(0x8000 | (rand() & 0x7FFF));
        candidate |= 1; // Make it odd
    } while (!miller_rabin(candidate, 10));
    
    return candidate;
}

// Montgomery REDC - performs x * R^(-1) mod N where R = 2^32
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


// RSA Modular Exponentiation using square-and-multiply algorithm
// Computes: value^exp mod N
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