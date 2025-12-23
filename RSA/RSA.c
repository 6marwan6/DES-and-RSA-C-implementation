#include <stdint.h>
/* some utilities functions for inverse calculation */
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

/* compute N^(-1) mod R where R = 2^32 */
static uint32_t compute_invN(uint32_t N)
{
    return mod_inverse(N, 1ULL << 32);
}

/* compute R^2 mod N where R = 2^32 */
static uint32_t compute_R2modN(uint32_t N)
{
    uint64_t R2 = 1;
    
    for (int i = 0; i < 64; i++) {
        R2 = (R2 << 1) % N;
    }
    
    return (uint32_t)R2;
}

/* RSA modular exponentiation
   result = value^exp mod N
*/

uint32_t rsa_modexp(uint32_t value, uint32_t exp,
                    uint32_t N, uint32_t invN, uint32_t R2modN)
{
    uint32_t valueM = to_mont(value, R2modN, N, invN);// to be implemented (convert to montgomery space)
    uint32_t resultM = to_mont(1, R2modN, N, invN);

    while (exp > 0) {
        
        if (exp & 1)
            resultM = mont_mul(resultM, valueM, N, invN); // to be implemented (montgomery multiplication)
        
        valueM = mont_mul(valueM, valueM, N, invN); // to be implemented (montgomery multiplication)  
        
        exp >>= 1;
    }
    
    return from_mont(resultM, N, invN);// to be implemented (convert from montgomery space to normal integer)
}


