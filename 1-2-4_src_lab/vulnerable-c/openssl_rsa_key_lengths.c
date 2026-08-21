#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>

/*
 * Training sample: RSA key length detection.
 * Static analysis should infer key length from the second argument of
 * RSA_generate_key_ex(rsa, bits, e, NULL).
 */

void generate_rsa_1024(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, e, NULL);  // weak key length
    RSA_free(rsa);
    BN_free(e);
}

void generate_rsa_2048(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, e, NULL);  // legacy / PQC migration target
    RSA_free(rsa);
    BN_free(e);
}

void generate_rsa_3072(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, 65537);
    RSA_generate_key_ex(rsa, 3072, e, NULL);  // stronger classical setting
    RSA_free(rsa);
    BN_free(e);
}

void generate_rsa_4096(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, 0x10001);
    RSA_generate_key_ex(rsa, 4096, e, NULL);  // stronger classical setting
    RSA_free(rsa);
    BN_free(e);
}

int main(void) {
    generate_rsa_1024();
    generate_rsa_2048();
    generate_rsa_3072();
    generate_rsa_4096();
    printf("RSA key length examples executed.\n");
    return 0;
}
