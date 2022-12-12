#include<iostream>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <assert.h>

using namespace std;

struct derivedKey {
    char* secret;
    size_t length;
};

typedef struct derivedKey derivedKey;


// EVP_PKEY *create_key(void)
// {
// 	EVP_PKEY_CTX *pctx, *kctx;
// 	EVP_PKEY_CTX *ctx;
// 	EVP_PKEY *pkey = NULL, *params = NULL;
// 	/* NB: assumes pkey, peerkey have been already set up */

//     /* Create the context for parameter generation */
// 	if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
// 		printf("Failed to create the context for parameter generation\n");
// 		return NULL;
// 	}

//     /* Initialise the parameter generation */
//     if (1 != EVP_PKEY_paramgen_init(pctx)) {
// 		printf("Failed to  Initialise the parameter generation\n");
// 		return NULL;
// 	}

//     /* We're going to use the ANSI X9.62 Prime 256v1 curve */
//     if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1)) {
// 		printf("Failed to create key curve\n");
// 		return NULL;
// 	}

//     /* Create the parameter object params */
//     if (!EVP_PKEY_paramgen(pctx, &params)) {
// 		printf("Failed to create  the parameter object params\n");
// 		return NULL;
// 	}

//     /* Create the context for the key generation */
//     if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) {
// 		printf("Failed to create the context for the key generation\n");
// 		return NULL;
// 	}

//     /* Generate the key */
// 	if (1 != EVP_PKEY_keygen_init(kctx)) {
// 		printf("Failed to generate key\n");
// 		return NULL;
// 	}

//     if (1 != EVP_PKEY_keygen(kctx, &pkey)) {
// 		printf("Failed to generate key\n");
// 		return NULL;
// 	}

// 	return pkey;
// }

// unsigned char *generate_secret(EVP_PKEY *pkey, EVP_PKEY *peerkey, size_t *secret_len) {
//     EVP_PKEY_CTX *ctx;
//     unsigned char *secret;

// 	/* Create the context for the shared secret derivation */
// 	if(NULL == (ctx = EVP_PKEY_CTX_new(pkey, NULL))) {
//         printf("Failed to create the context for the shared secret derivation\n");
// 		return NULL;
//     }

// 	/* Initialise */
// 	if(1 != EVP_PKEY_derive_init(ctx)) {
//         printf("Failed to initialise\n");
// 		return NULL;
//     }

// 	/* Provide the peer public key */
// 	if(1 != EVP_PKEY_derive_set_peer(ctx, peerkey)){
//         printf("Failed to provide the peer public key\n");
// 		return NULL;
//     }

// 	/* Determine buffer length for shared secret */
// 	if(1 != EVP_PKEY_derive(ctx, NULL, secret_len)) {
//         printf("Failed to determine buffer length for shared secret\n");
// 		return NULL;
//     }

// 	/* Create the buffer */
// 	if(NULL == (secret = (unsigned char*)OPENSSL_malloc(*secret_len))) {
//         printf("Failed to create the buffer\n");
// 		return NULL;
//     };

// 	/* Derive the shared secret */
// 	if(1 != (EVP_PKEY_derive(ctx, secret, secret_len))) {
//         printf("Failed to derive the shared secret\n");
// 		return NULL;
//     };

// 	EVP_PKEY_CTX_free(ctx);
// 	EVP_PKEY_free(peerkey);
// 	EVP_PKEY_free(pkey);

// 	/* Never use a derived secret directly. Typically it is passed
// 	 * through some hash function to produce a key */
// 	return secret;
// }

void handleErrors() {
    printf("error.\n");
}

void handleDerivationErrors(int x){
    printf("\n\nDerivation Failed...");
    printf("%d", x);
}

EVP_PKEY* generateKey(int NID){
    EVP_PKEY_CTX *paramGenCtx = NULL, *keyGenCtx = NULL;
    EVP_PKEY *params= NULL, *keyPair= NULL;

    paramGenCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if(!EVP_PKEY_paramgen_init(paramGenCtx)) handleErrors();

    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramGenCtx, NID);

    EVP_PKEY_paramgen(paramGenCtx, &params);

    keyGenCtx = EVP_PKEY_CTX_new(params, NULL);

    if(!EVP_PKEY_keygen_init(keyGenCtx)) handleErrors();

    if(!EVP_PKEY_keygen(keyGenCtx, &keyPair)) handleErrors();

    EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(keyPair);

    const BIGNUM *privKey = EC_KEY_get0_private_key(ecKey);

    const EC_POINT *pubPoint = EC_KEY_get0_public_key(ecKey);

    BIGNUM *x = BN_new();

    BIGNUM *y = BN_new();

    EC_POINT_get_affine_coordinates_GFp(EC_GROUP_new_by_curve_name(NID), pubPoint, x, y, NULL);

    printf("\nprivate : ");

    BN_print_fp(stdout, privKey);

    printf("\npubX : ");

    BN_print_fp(stdout, x);

    printf("\npubY : ");

    BN_print_fp(stdout, y);

    EVP_PKEY_CTX_free(paramGenCtx);
    EVP_PKEY_CTX_free(keyGenCtx);

    return keyPair;
}

/**
    Takes in a private key and extracts the public key from it.
*/
EVP_PKEY* extractPublicKey(EVP_PKEY *privateKey, int NID){
    EC_KEY *ecKey = EVP_PKEY_get1_EC_KEY(privateKey);
    const EC_POINT *ecPoint = EC_KEY_get0_public_key(ecKey);

    EVP_PKEY *publicKey = EVP_PKEY_new();

    EC_KEY *pubEcKey = EC_KEY_new_by_curve_name(NID);

    EC_KEY_set_public_key(pubEcKey, ecPoint);

    EVP_PKEY_set1_EC_KEY(publicKey, pubEcKey);

    EC_KEY_free(ecKey);
    // EC_POINT_free(ecPoint);

    return publicKey;
}

/**
    Takes in the private key and peer public key and spits out the derived shared secret.
*/
derivedKey* deriveShared(EVP_PKEY *publicKey, EVP_PKEY *privateKey){

    derivedKey *dk = (derivedKey *)malloc(sizeof(derivedKey));

    EVP_PKEY_CTX *derivationCtx = NULL;

    derivationCtx = EVP_PKEY_CTX_new(privateKey, NULL);

    EVP_PKEY_derive_init(derivationCtx);

    EVP_PKEY_derive_set_peer(derivationCtx, publicKey);

	if(1 != EVP_PKEY_derive(derivationCtx, NULL, &dk->length)) handleDerivationErrors(0);

	if(NULL == (dk->secret = (char *)OPENSSL_malloc(dk->length))) handleDerivationErrors(1);

	if(1 != (EVP_PKEY_derive(derivationCtx, (unsigned char *)dk->secret, &dk->length))) handleDerivationErrors(2);

        EVP_PKEY_CTX_free(derivationCtx);

	return dk;
}

// int main() {
//     EVP_PKEY *alice = generateKey(NID_secp521r1);
//     EVP_PKEY *bob = generateKey(NID_secp521r1);
//     EVP_PKEY *alice_public = extractPublicKey(alice, NID_secp521r1);
//     EVP_PKEY *bob_public = extractPublicKey(bob, NID_secp521r1);
//     derivedKey *sec_alice = deriveShared(bob_public, alice);
//     derivedKey *sec_bob = deriveShared(alice_public, bob);
//     BIGNUM *secretAliceBN = BN_new();
//     BIGNUM *secretBobBN = BN_new();
//     BN_bin2bn((const unsigned char *)sec_alice->secret, sec_alice->length, secretAliceBN);
//     BN_bin2bn((const unsigned char *)sec_bob->secret, sec_bob->length, secretBobBN);
//     printf("\n\nSecret computed by Alice :\n");
//     BN_print_fp(stdout, secretAliceBN);
//     printf("\n\nSecret computed by Bob :\n");
//     BN_print_fp(stdout, secretBobBN);
// }
