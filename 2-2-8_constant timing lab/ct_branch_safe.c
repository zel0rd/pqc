#include <stdint.h>
#include <stdio.h>
#include <valgrind/memcheck.h>

static uint32_t ct_eq_mask_u32(uint32_t x, uint32_t y)
{
    uint32_t q = x ^ y;
    q |= (uint32_t)(0U - q);
    q >>= 31;
    return q - 1U;
}

static uint32_t safe_lookup(const uint32_t secret)
{
    static const uint32_t table[4] = {10, 20, 30, 40};
    uint32_t selected = 0U;

    /* 모든 원소를 동일하게 접근하고 mask로 선택 */
    for (uint32_t i = 0; i < 4U; i++) {
        uint32_t mask = ct_eq_mask_u32(secret & 3U, i);
        selected |= table[i] & mask;
    }

    /* secret bit에 따른 값을 mask 연산으로 선택 */
    uint32_t bit = secret & 1U;
    uint32_t bit_mask = 0U - bit;
    uint32_t add = (1U & bit_mask) | (2U & ~bit_mask);

    return selected + add;
}

int main(void)
{
    uint32_t secret = 3U;

    printf("[수정 구현] branchless/full-scan 검사\n");

    VALGRIND_MAKE_MEM_UNDEFINED(&secret, sizeof(secret));

    uint32_t result = safe_lookup(secret);

    VALGRIND_MAKE_MEM_DEFINED(&result, sizeof(result));

    printf("result = %u\n", result);
    return 0;
}
