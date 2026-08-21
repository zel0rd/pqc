#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>

int sha256_hash(const unsigned char *msg, size_t len, unsigned char *out, unsigned int *out_len) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) return 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) return 0;
    if (EVP_DigestUpdate(ctx, msg, len) != 1) return 0;
    if (EVP_DigestFinal_ex(ctx, out, out_len) != 1) return 0;
    EVP_MD_CTX_free(ctx);
    return 1;
}

int main(void) {
    unsigned char random_bytes[32];
    if (RAND_bytes(random_bytes, sizeof(random_bytes)) != 1) {
        return 1;
    }
    printf("Secure example: SHA-256 and RAND_bytes.\n");
    return 0;
}
