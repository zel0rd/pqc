#include <stdio.h>

/*
 * RSA-like parameters for static analysis training.
 * Do not use these values in production.
 */

static const char *RSA_N =
    "C4F3A1B2E9D8C7A6F5E4D3C2B1A09876"
    "1234567890ABCDEF1234567890ABCDEF"
    "FEDCBA0987654321FEDCBA0987654321"
    "AABBCCDDEEFF00112233445566778899";

static const char *RSA_E = "010001";  // 65537

static const char *RSA_D =
    "12AB34CD56EF789012AB34CD56EF7890"
    "99887766554433221100FFEEDDCCBBAA";

int main(void) {
    printf("RSA modulus candidate: %s\n", RSA_N);
    printf("RSA public exponent: %s\n", RSA_E);
    return 0;
}
