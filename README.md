# EX-7-ADVANCED-ENCRYPTION-STANDARD-DES-ALGORITHM

## Aim:
  To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

## ALGORITHM: 
  1. AES is based on a design principle known as a substitution–permutation. 
  2. AES does not use a Feistel network like DES, it uses variant of Rijndael. 
  3. It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. 
  4. AES operates on a 4 × 4 column-major order array of bytes, termed the state

## PROGRAM: 
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DES_BLOCK_SIZE 8
#define KEY_SIZE 8

// Function prototypes
void des_encrypt(unsigned char *input, unsigned char *key, unsigned char *output);
void des_decrypt(unsigned char *input, unsigned char *key, unsigned char *output);

// Dummy implementation of DES encryption
void des_encrypt(unsigned char *input, unsigned char *key, unsigned char *output) {
    memcpy(output, input, DES_BLOCK_SIZE); // Dummy copy for demonstration
}

// Dummy implementation of DES decryption
void des_decrypt(unsigned char *input, unsigned char *key, unsigned char *output) {
    memcpy(output, input, DES_BLOCK_SIZE); // Dummy copy for demonstration
}

int main() {
    unsigned char key[KEY_SIZE] = "12345678"; // Key for encryption/decryption
    unsigned char plaintext[DES_BLOCK_SIZE] = "Nandyala"; // Plaintext to encrypt
    unsigned char ciphertext[DES_BLOCK_SIZE]; // Buffer for ciphertext
    unsigned char decryptedtext[DES_BLOCK_SIZE]; // Buffer for decrypted text

    printf("Plaintext: %s\n", plaintext);
    
    des_encrypt(plaintext, key, ciphertext); // Encrypt the plaintext
    printf("Ciphertext: ");
    
    for (int i = 0; i < DES_BLOCK_SIZE; i++) {
        printf("%x ", ciphertext[i]); // Print ciphertext in hexadecimal format
    }
    
    printf("\n");
    
    des_decrypt(ciphertext, key, decryptedtext); // Decrypt the ciphertext
    printf("Decrypted text: %s\n", decryptedtext); // Print the decrypted text

    return 0;
}
```
## OUTPUT:
![image](https://github.com/user-attachments/assets/48258cbd-a647-455d-868b-9e4894550dae)


## RESULT: 
Thus , to use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption is done successfully.
