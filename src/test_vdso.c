#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <vmpl/sys.h>
#include <vmpl/vmpl.h>

#include "benchmark.h"

static uint64_t get_time(void)
{
    struct timespec ts;
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

START_TEST(test_vdso)
{
    VMPL_ENTER;
    int a = getpid();
    int b = getpid();

    ck_assert_int_eq(a, b);
}
END_TEST

START_TEST(test_time_vdso)
{
    VMPL_ENTER;
    uint64_t start_time, end_time;
    uint64_t total_time = 0;

    start_time = get_time();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        time(NULL);
    }
    end_time = get_time();
    total_time = end_time - start_time;

    printf("Elapsed time: %lu ns\n", total_time);
}
END_TEST

START_TEST(test_time_syscall)
{
    VMPL_ENTER;
    uint64_t start_time, end_time;
    uint64_t total_time = 0;
    time_t t;

    start_time = get_time();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        syscall(SYS_time, &t);
    }
    end_time = get_time();
    total_time = end_time - start_time;

    printf("Elapsed time: %lu ns\n", total_time);

}
END_TEST

START_TEST(test_time)
{
    VMPL_ENTER;
    pid_t pid;
    uint64_t start_time;
    uint64_t end_time;
    uint64_t total_time = 0;

    start_time = get_time();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        pid = getpid();
    }
    end_time = get_time();
    total_time = end_time - start_time;


    printf("Elapsed time: %lu ns\n", total_time);

    start_time = rdtsc();
    for (int i = 0; i < NUM_ITERATIONS; i++)
    {
        pid = getpid();
    }
    end_time = rdtsc();
    total_time = end_time - start_time;

    printf("Average time: %lu cycles\n", total_time / NUM_ITERATIONS);
}
END_TEST

Suite *vdso_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("vDSO");

    /* Core test case */
    tc_core = tcase_create("vDSO");
    tcase_add_test(tc_core, test_vdso);
    tcase_add_test(tc_core, test_time_vdso);
    tcase_add_test(tc_core, test_time_syscall);
    tcase_add_test(tc_core, test_time);

    suite_add_tcase(s, tc_core);

    return s;
}