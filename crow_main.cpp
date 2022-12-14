#include <iostream>
#include "crow.h"
#include "openssl_ecdh.h"
#include "aes.h"

using namespace std;

int main()
{
    crow::SimpleApp app;

    CROW_ROUTE(app, "/")
    ([]()
     { return "Hello world"; });

    CROW_ROUTE(app, "/encrypt").methods("POST"_method)
    ([](const crow::request& req) {
        crow::json::wvalue res;

        EVP_PKEY *alice = generateKey(NID_secp521r1);
        EVP_PKEY *bob = generateKey(NID_secp521r1);
        EVP_PKEY *alice_public = extractPublicKey(alice, NID_secp521r1);
        EVP_PKEY *bob_public = extractPublicKey(bob, NID_secp521r1);
        derivedKey *sec_alice = deriveShared(bob_public, alice);
        derivedKey *sec_bob = deriveShared(alice_public, bob);
        BIGNUM *secretAliceBN = BN_new();
        BIGNUM *secretBobBN = BN_new();
        BN_bin2bn((const unsigned char *)sec_alice->secret, sec_alice->length, secretAliceBN);
        BN_bin2bn((const unsigned char *)sec_bob->secret, sec_bob->length, secretBobBN);
        printf("\n\nSecret computed by Alice :\n");
        BN_print_fp(stdout, secretAliceBN);
        printf("\n\nSecret computed by Bob :\n");
        BN_print_fp(stdout, secretBobBN);

        /* A 128 bit IV */
        unsigned char *iv = (unsigned char *)"0123456789012345";

        /* Message to be encrypted */
        unsigned char *plaintext =
            (unsigned char *)"The quick brown fox jumps over the lazy dog";

        /*
        * Buffer for ciphertext. Ensure the buffer is long enough for the
        * ciphertext which may be longer than the plaintext, depending on the
        * algorithm and mode.
        */
        unsigned char ciphertext[128];

        /* Buffer for the decrypted text */
        unsigned char decryptedtext[128];

        int decryptedtext_len, ciphertext_len;

        /* Encrypt the plaintext */
        ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), (unsigned char *)secretAliceBN, iv,
                                ciphertext);

        /* Do something useful with the ciphertext here */
        printf("Ciphertext is:\n");
        BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

        // reap memory buffer
        char *ptr = NULL;
        long len = Base64Encode(ciphertext, &ptr, ciphertext_len);

        ostringstream os;
        os << ptr;

        res["message"] = os.str();
        return res;
    });

    app.port(18080).multithreaded().run();
}
