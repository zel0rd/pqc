#include <stdio.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>

int main(void) {
    EC_KEY *ec_key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);

    if (ec_key == NULL) {
        printf("Failed to create EC key.\n");
        return 1;
    }

    EC_KEY_generate_key(ec_key);

    PEM_write_EC_PUBKEY(stdout, ec_key);

    EC_KEY_free(ec_key);
    return 0;
}
