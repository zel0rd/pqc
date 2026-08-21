#define _GNU_SOURCE
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <valgrind/memcheck.h>

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static inline uint64_t ticks(void)
{
    unsigned int aux;
    return __rdtscp(&aux);
}
#else
static inline uint64_t ticks(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
#endif

#define Q 3329U
#define D 10U
#define REPEAT 2000000U

/*
 * KyberSlash형 교육용 취약 예제:
 * 분모 Q는 공개값이지만 분자가 secret에 의존한다.
 *
 * volatile divisor를 사용하여 컴파일러가 division을 reciprocal
 * multiplication으로 완전히 치환하는 것을 방지한다.
 */
__attribute__((noinline))
static uint32_t vulnerable_compress(uint32_t secret)
{
    volatile uint32_t divisor = Q;
    return ((secret << D) + (Q / 2U)) / divisor;
}

/*
 * 교육용 수정 예제:
 * 상수 Q에 대한 reciprocal multiplication을 사용한다.
 * 실제 암호 구현에서는 범위 증명과 정확한 rounding 검증이 필요하다.
 */
__attribute__((noinline))
static uint32_t reciprocal_compress(uint32_t secret)
{
    uint64_t numerator = ((uint64_t)secret << D) + (Q / 2U);

    /*
     * floor(n / 3329)를 근사한 뒤 보정한다.
     * 2^32 / 3329의 올림값 사용
     */
    const uint64_t reciprocal = ((1ULL << 32) + Q - 1U) / Q;
    uint32_t qhat = (uint32_t)((numerator * reciprocal) >> 32);

    /* 공개 상수 연산이며, 비교 결과를 mask로 반영 */
    uint64_t product = (uint64_t)qhat * Q;
    uint64_t too_large = (uint64_t)-(product > numerator);
    qhat -= (uint32_t)(too_large & 1U);

    product = (uint64_t)qhat * Q;
    uint64_t remainder = numerator - product;
    uint64_t too_small = (uint64_t)-(remainder >= Q);
    qhat += (uint32_t)(too_small & 1U);

    return qhat;
}

static uint64_t benchmark(uint32_t (*fn)(uint32_t), uint32_t secret)
{
    volatile uint32_t sink = 0U;
    uint64_t start = ticks();

    for (uint32_t i = 0; i < REPEAT; i++) {
        sink ^= fn(secret + (i & 1U));
    }

    uint64_t end = ticks();

    if (sink == 0xFFFFFFFFU) {
        fprintf(stderr, "ignore: %u\n", sink);
    }

    return end - start;
}

int main(void)
{
    uint32_t secret = 1234U;

    puts("==================================================");
    puts("KyberSlash형 secret-dependent division 교육 실습");
    puts("==================================================");

    puts("\n[1] 일반 Valgrind taint 검사");
    puts("secret이 division operand로 사용되지만,");
    puts("branch/address에 사용되지 않으면 Valgrind가 놓칠 수 있습니다.");

    VALGRIND_MAKE_MEM_UNDEFINED(&secret, sizeof(secret));
    uint32_t out = vulnerable_compress(secret);
    VALGRIND_MAKE_MEM_DEFINED(&out, sizeof(out));
    VALGRIND_MAKE_MEM_DEFINED(&secret, sizeof(secret));

    printf("vulnerable_compress 결과 = %u\n", out);

    puts("\n[2] 입력 클래스별 반복 실행시간 비교");
    puts("환경에 따라 차이가 작거나 방향이 달라질 수 있습니다.");

    const uint32_t class_a = 1U;
    const uint32_t class_b = Q - 2U;

    uint64_t v_a = benchmark(vulnerable_compress, class_a);
    uint64_t v_b = benchmark(vulnerable_compress, class_b);
    uint64_t s_a = benchmark(reciprocal_compress, class_a);
    uint64_t s_b = benchmark(reciprocal_compress, class_b);

    printf("취약 division 구현  class A: %" PRIu64 "\n", v_a);
    printf("취약 division 구현  class B: %" PRIu64 "\n", v_b);
    printf("차이: %" PRIu64 "\n", (v_a > v_b) ? v_a - v_b : v_b - v_a);

    printf("\n수정 reciprocal 구현 class A: %" PRIu64 "\n", s_a);
    printf("수정 reciprocal 구현 class B: %" PRIu64 "\n", s_b);
    printf("차이: %" PRIu64 "\n", (s_a > s_b) ? s_a - s_b : s_b - s_a);

    puts("\n[해석]");
    puts("- Valgrind 무경고는 constant-time 보장의 증명이 아닙니다.");
    puts("- binary에 div/idiv가 존재하는지 확인해야 합니다.");
    puts("- 실제 보안 검증에는 dudect, instruction taint 분석, 실기기 측정이 필요합니다.");

    return 0;
}
