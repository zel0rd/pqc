#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char key[16] = "0123456789abcdef";
    unsigned char plaintext[32] = "hello crypto static lab";
    unsigned char ciphertext[64];

    int len = 0;
    int ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, strlen((char *)plaintext));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    printf("ciphertext length: %d\n", ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return 0;
}
