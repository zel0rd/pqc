#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <string.h>

void weak_hash(const unsigned char *msg, size_t len) {
    MD5_CTX md5;
    unsigned char md5_out[MD5_DIGEST_LENGTH];
    MD5_Init(&md5);
    MD5_Update(&md5, msg, len);
    MD5_Final(md5_out, &md5);

    SHA_CTX sha1;
    unsigned char sha1_out[SHA_DIGEST_LENGTH];
    SHA1_Init(&sha1);
    SHA1_Update(&sha1, msg, len);
    SHA1_Final(sha1_out, &sha1);
}

void weak_public_key(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);
    RSA_generate_key_ex(rsa, 1024, e, NULL);
    BN_free(e);
    RSA_free(rsa);

    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_free(ec);
}

int main(void) {
    const unsigned char msg[] = "crypto policy test";
    weak_hash(msg, strlen((const char *)msg));
    weak_public_key();
    printf("This file intentionally uses weak crypto.\n");
    return 0;
}
