#ifndef AES_H
#define AES_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
int calcDecodeLength(const char *b64input);
int Base64Decode(char *b64message, char **buffer);
long Base64Encode(unsigned char *message, char **buffer, int ciphertext_len);

#endif
