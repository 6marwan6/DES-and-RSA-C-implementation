# DES and RSA Implementations

Complete implementations of DES (Data Encryption Standard) and RSA encryption algorithms in C.

## Features

### DES
- Full DES encryption and decryption
- Proper endianness handling for cross-platform compatibility
- Support for any file size (multiples of 8 bytes)
- Binary file I/O

### RSA
- RSA key generation
- Encryption/decryption with public/private keys
- Constant-time Montgomery multiplication (Task 4)
- Hexadecimal file format

## Compilation

### DES
Compile the program using GCC with C99 standard:

```powershell
gcc -o main.exe main.c -std=c99 
```

### RSA
```powershell
gcc -O3 -o RSA.exe RSA/RSA.c
```

## Usage

### DES
```
main.exe <e|d> <keyfile> <inputfile> <outputfile>
```

**Arguments:**
- `<e|d>`: Mode - `e` for encryption, `d` for decryption
- `<keyfile>`: Path to the 8-byte binary key file
- `<inputfile>`: Path to the input file to encrypt/decrypt
- `<outputfile>`: Path where the output will be written

**Examples:**
```powershell
# Encrypt a file
.\main.exe e files\key.bin files\input.bin encrypted.bin

# Decrypt a file
.\main.exe d files\key.bin encrypted.bin decrypted.bin
```

### RSA
```
RSA.exe <g|e|d> [key_files] [data_files]
```

**Arguments:**
- `g` - Generate RSA keys: `RSA.exe g public_key.txt private_key.txt`
- `e` - Encrypt: `RSA.exe e public_key.txt plaintext.txt ciphertext.txt`
- `d` - Decrypt: `RSA.exe d private_key.txt ciphertext.txt plaintext.txt`

**Examples:**
```powershell
# Generate keys
.\RSA.exe g public_key.txt private_key.txt

# Encrypt plaintext
.\RSA.exe e public_key.txt plaintext.txt ciphertext.txt

# Decrypt ciphertext
.\RSA.exe d private_key.txt ciphertext.txt plaintext.txt
```

**File Formats:**
- Key files: Hexadecimal format (e.g., `e n` or `d n`)
- Data files: Hexadecimal 32-bit values

## Technical Details

### DES Implementation
- **Algorithm**: DES (Data Encryption Standard)
- **Block size**: 64 bits (8 bytes)
- **Key size**: 64 bits (56 bits + 8 parity bits)
- **Rounds**: 16 Feistel rounds
- Written in C99
- Uses standard DES permutation tables (IP, FP, E, P, PC1, PC2)
- Implements all 8 S-boxes
- Automatic endianness handling for little-endian systems (Windows, Linux x86/x64)
- Key generation with proper left rotations per round

### RSA Implementation
- **Algorithm**: RSA with Montgomery multiplication
- **Key size**: 32-bit modulus (for demonstration)
- **Modular exponentiation**: Square-and-multiply algorithm
- **Security features**:
  - Constant-time Montgomery reduction (no DIV on secret data)
  - Resistant to timing side-channel attacks
  - R = 2^32 (Montgomery parameter)
- **Key generation**: 
  - N = p × q
  - φ(N) = (p-1)(q-1)
  - d = e^(-1) mod φ(N) using Extended Euclidean Algorithm
- **Precomputed values**:
  - invN = N^(-1) mod R
  - R2modN = R^2 mod N

## Files
- `main.c` - DES implementation with encryption/decryption core and file I/O
- `files/` - Test data directory
- `RSA/` - RSA implementation


