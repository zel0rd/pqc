#include <stdio.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

int main(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    BN_set_word(e, RSA_F4);

    RSA_generate_key_ex(rsa, 2048, e, NULL);

    PEM_write_RSAPublicKey(stdout, rsa);

    RSA_free(rsa);
    BN_free(e);

    return 0;
}
