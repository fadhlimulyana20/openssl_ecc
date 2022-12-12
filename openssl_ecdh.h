#ifndef PLAYER_H
#define PLAYER_H

#include <openssl/evp.h>
#include <openssl/ec.h>

struct derivedKey {
    char* secret;
    size_t length;
};

typedef struct derivedKey derivedKey;

EVP_PKEY* generateKey(int NID);
EVP_PKEY* extractPublicKey(EVP_PKEY *privateKey, int NID);
derivedKey* deriveShared(EVP_PKEY *publicKey, EVP_PKEY *privateKey);

#endif
