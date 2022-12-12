#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <math.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int calcDecodeLength(const char *b64input)
{ // Calculates the length of a decoded base64 string
    int len = strlen(b64input);
    int padding = 0;

    if (b64input[len - 1] == '=' && b64input[len - 2] == '=') // last two chars are =
        padding = 2;
    else if (b64input[len - 1] == '=') // last char is =
        padding = 1;

    return (int)len * 0.75 - padding;
}

int Base64Decode(char *b64message, char **buffer)
{ // Decodes a base64 encoded string
    BIO *bio, *b64;
    int decodeLen = calcDecodeLength(b64message),
        len = 0;
    *buffer = (char *)malloc(decodeLen + 1);
    FILE *stream = fmemopen(b64message, strlen(b64message), "r");

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Do not use newlines to flush buffer
    len = BIO_read(bio, *buffer, strlen(b64message));
    // Can test here if len == decodeLen - if not, then return an error
    (*buffer)[len] = '\0';

    BIO_free_all(bio);
    fclose(stream);

    return (0); // success
}

int Base64Encode(char *message, char **buffer)
{
    BIO *bio, *b64;
    FILE *stream;
    int encodedSize = 4 * ceil((double)strlen(message) / 3);
    *buffer = (char *)malloc(encodedSize + 1);

    stream = fmemopen(*buffer, encodedSize + 1, "w");
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_fp(stream, BIO_NOCLOSE);
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); // Ignore newlines - write everything in one line
    BIO_write(bio, message, strlen(message));
    BIO_flush(bio);
    BIO_free_all(bio);
    fclose(stream);

    return (0); // success
}

// References
// https://stackoverflow.com/questions/71073777/openssl-bio-read-on-string-returns-incomplete-base64-encoding
// https://gist.github.com/barrysteyn/4409525

int main(void)
{
    /*
     * Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */

    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"20EAE714A5DC2F1F26DF7F88F42A70DFD19FC1780F9AE8CD720232E40ACD5CD5416CB917AAB2EEC521E77D5F5AD36C2ED579090D90B9A39A7015941D0C608BB5B3";

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
    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv,
                             ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

     // configure base64 filter
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    // configure a memory bio
    BIO *bmem = BIO_new(BIO_s_mem());

    // chain bios
    BIO *bio = BIO_push(b64, bmem);

    // write to target chain and flush
    BIO_write(bio, ciphertext, ciphertext_len);
    BIO_flush(bio);

    // reap memory buffer
    char *ptr = NULL;
    long len = BIO_get_mem_data(bmem, &ptr);

    char *base64DecodeOutput;
    Base64Decode(ptr, &base64DecodeOutput);
    printf("Output: %s\n", base64DecodeOutput);
    BIO_dump_fp(stdout, (const char *)base64DecodeOutput, ciphertext_len);

    // dump the converted data to stdout
    // fwrite(ptr, (size_t)len, 1, stdout);
    // fputc('\n', stdout);
    // fflush(stdout);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt((unsigned char *)base64DecodeOutput, ciphertext_len, key, iv,
                                decryptedtext);

    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';

    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    return 0;
}
