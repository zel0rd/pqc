#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

/*
 * OpenSSL key length examples for static crypto asset discovery.
 * This file intentionally contains multiple AES/RSA/ECC key-size patterns.
 * Do not use this code in production.
 */

void aes_key_length_examples(void) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    unsigned char aes128_key[16] = "0123456789abcdef";
    unsigned char aes192_key[24] = "abcdefghijklmnopqrstuvwx";
    unsigned char aes256_key[32] = "abcdefghijklmnopqrstuvwxyz123456";

    unsigned char iv[16] = "0000000000000000";
    unsigned char input[32] = "key length detection example";
    unsigned char output[64];
    int len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes128_key, iv);
    EVP_EncryptUpdate(ctx, output, &len, input, strlen((char *)input));

    EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, aes192_key, iv);
    EVP_EncryptUpdate(ctx, output, &len, input, strlen((char *)input));

    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, aes256_key, iv);
    EVP_EncryptUpdate(ctx, output, &len, input, strlen((char *)input));

    EVP_CIPHER_CTX_free(ctx);
}

void rsa_key_length_examples(void) {
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    RSA *rsa1024 = RSA_new();
    RSA_generate_key_ex(rsa1024, 1024, e, NULL);  // weak / legacy

    RSA *rsa2048 = RSA_new();
    RSA_generate_key_ex(rsa2048, 2048, e, NULL);  // common legacy baseline

    RSA *rsa3072 = RSA_new();
    RSA_generate_key_ex(rsa3072, 3072, e, NULL);  // stronger classical RSA

    RSA_free(rsa1024);
    RSA_free(rsa2048);
    RSA_free(rsa3072);
    BN_free(e);
}

void ecc_key_length_examples(void) {
    EC_KEY *p256 = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // 256-bit curve
    EC_KEY *p384 = EC_KEY_new_by_curve_name(NID_secp384r1);        // 384-bit curve
    EC_KEY *p521 = EC_KEY_new_by_curve_name(NID_secp521r1);        // 521-bit curve

    EC_KEY_generate_key(p256);
    EC_KEY_generate_key(p384);
    EC_KEY_generate_key(p521);

    EC_KEY_free(p256);
    EC_KEY_free(p384);
    EC_KEY_free(p521);
}

int main(void) {
    aes_key_length_examples();
    rsa_key_length_examples();
    ecc_key_length_examples();
    printf("OpenSSL key length examples executed.\n");
    return 0;
}
