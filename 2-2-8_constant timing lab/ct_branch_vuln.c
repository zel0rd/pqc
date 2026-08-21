#include <stdint.h>
#include <stdio.h>
#include <valgrind/memcheck.h>

static uint32_t vulnerable_lookup(const uint32_t secret)
{
    static const uint32_t table[4] = {10, 20, 30, 40};

    /* 취약점 1: 비밀값에 따른 조건 분기 */
    if (secret & 1U) {
        /* 취약점 2: 비밀값에 따른 메모리 주소 접근 */
        return table[secret & 3U] + 1U;
    }

    return table[secret & 3U] + 2U;
}

int main(void)
{
    uint32_t secret = 3U;

    printf("[취약 구현] secret-dependent branch/address 검사\n");

    /* secret을 비밀(tainted/undefined)로 표시 */
    VALGRIND_MAKE_MEM_UNDEFINED(&secret, sizeof(secret));

    uint32_t result = vulnerable_lookup(secret);

    /* 결과 출력은 실습 harness의 false positive를 피하기 위해 다시 defined 처리 */
    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));

    printf("result = %u\n", result);
    return 0;
}
