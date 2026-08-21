#include <stdio.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

int main(void) {
    unsigned char input[] = "crypto asset static analysis lab";

    unsigned char md5_out[MD5_DIGEST_LENGTH];
    unsigned char sha1_out[SHA_DIGEST_LENGTH];

    MD5(input, strlen((char *)input), md5_out);
    SHA1(input, strlen((char *)input), sha1_out);

    printf("MD5 and SHA1 calculated.\n");
    return 0;
}
