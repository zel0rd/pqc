#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

/*
 * Training sample: AES key length detection in OpenSSL EVP code.
 * The scanner should infer AES-128/192/256 from EVP function names
 * and from key buffer sizes 16/24/32 bytes.
 */

void encrypt_aes128(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key128[16] = "0123456789abcdef";
    unsigned char iv[12] = "12345678901";
    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key128, iv);
    EVP_CIPHER_CTX_free(ctx);
}

void encrypt_aes192(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key192[24] = "abcdefghijklmnopqrstuvwx";
    unsigned char iv[16] = "0000000000000000";
    EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key192, iv);
    EVP_CIPHER_CTX_free(ctx);
}

void encrypt_aes256(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key256[32] = "abcdefghijklmnopqrstuvwxyz123456";
    unsigned char iv[12] = "abcdefghijkl";
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key256, iv);
    EVP_CIPHER_CTX_free(ctx);
}

int main(void) {
    encrypt_aes128();
    encrypt_aes192();
    encrypt_aes256();
    printf("AES key length examples executed.\n");
    return 0;
}
