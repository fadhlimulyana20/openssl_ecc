#include <iostream>
#include <openssl/ec.h>
#include <openssl/pem.h>

int main() {
    char* priv = "-----BEGIN PRIVATE KEY-----\nMIHuAgEAMBAGByqGSM49AgEGBSuBBAAjBIHWMIHTAgEBBEIBrLdqu3LceL6rZ8sf\nTWeWGMi5jXwVPR/ptMrskmg0VGzuVvyLgL+F9bc8D8lJqQqEpQcm9N8skuJW56OV\nN5lHHu2hgYkDgYYABAFWz+Mq5sA6xHqCOEFtWSfSsl0kFehgQudAHBmzsECf20JT\nBHpNHtCFpAAjR9uw2ZCXqS7jnM9iaJ4iARbwBcpm8QF3Ef5PGH8HQrMvhsFMpGl5\nbt7ERT2scYHXzmLAy47V5fEi0HA9RD7m3Bn1O5nQJc7D/0Y9a/BFa3nclzAXuk8A\nvA==\n-----END PRIVATE KEY-----";
    char* pub = "-----BEGIN PUBLIC KEY-----\nMIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBVs/jKubAOsR6gjhBbVkn0rJdJBXo\nYELnQBwZs7BAn9tCUwR6TR7QhaQAI0fbsNmQl6ku45zPYmieIgEW8AXKZvEBdxH+\nTxh/B0KzL4bBTKRpeW7exEU9rHGB185iwMuO1eXxItBwPUQ+5twZ9TuZ0CXOw/9G\nPWvwRWt53JcwF7pPALw=\n-----END PUBLIC KEY-----";

    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, priv, strlen(priv));

    EVP_PKEY* pkey=0;
    PEM_read_bio_PrivateKey(bo, &pkey, 0, 0);
    PEM_read_bio_PUBKEY(bo, &pkey, 0, 0);
    
    BIO_free(bo);

    EC_KEY* myecc = EVP_PKEY_get1_EC_KEY(pkey);
    const EC_GROUP *ecgrp = EC_KEY_get0_group(myecc);

    BIO* outbio  = BIO_new(BIO_s_file());
    outbio = BIO_new_fp(stdout, BIO_NOCLOSE);

    BIO_printf(outbio, "ECC Key size: %d bit\n", EVP_PKEY_bits(pkey));
    BIO_printf(outbio, "ECC Key type: %s\n", OBJ_nid2sn(EC_GROUP_get_curve_name(ecgrp)));

    if(!PEM_write_bio_PrivateKey(outbio, pkey, NULL, NULL, 0, 0, NULL))
    BIO_printf(outbio, "Error writing private key data in PEM format");

    if(!PEM_write_bio_PUBKEY(outbio, pkey))
    BIO_printf(outbio, "Error writing public key data in PEM format");

}
