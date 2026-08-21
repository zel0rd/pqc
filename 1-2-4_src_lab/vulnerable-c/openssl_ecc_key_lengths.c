#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>

/*
 * Training sample: ECC key length detection.
 * Static analysis should infer approximate security/key size from curve NIDs.
 */

void create_p256(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(key);
    EC_KEY_free(key);
}

void create_p384(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp384r1);
    EC_KEY_generate_key(key);
    EC_KEY_free(key);
}

void create_p521(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp521r1);
    EC_KEY_generate_key(key);
    EC_KEY_free(key);
}

void create_secp256k1(void) {
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(key);
    EC_KEY_free(key);
}

int main(void) {
    create_p256();
    create_p384();
    create_p521();
    create_secp256k1();
    printf("ECC key length examples executed.\n");
    return 0;
}
