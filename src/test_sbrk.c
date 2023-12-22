#include <stdio.h>
#include <unistd.h>
#include <check.h>

// Test case setup
void setup(void) {
    // Add any setup code here
}

// Test case teardown
void teardown(void) {
    // Add any teardown code here
}

// Test case
START_TEST(test_sbrk_allocation) {
    // 使用 sbrk 分配 4KB 内存
    void *mem = sbrk(4096);
    ck_assert_ptr_ne(mem, (void *)-1);

    // 写入内存
    char *buf = (char *)mem;
    for (int i = 0; i < 4096; i++) {
        buf[i] = i % 256;
    }

    // 读取并打印内存
    for (int i = 0; i < 4096; i++) {
        if (i % 16 == 0) {
            printf("\n");
        }
        printf("%02x ", (unsigned char)buf[i]);
    }
    printf("\n");
}
END_TEST

// Test suite
Suite *sbrk_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("sbrk");
    tc_core = tcase_create("core");

    // Add test case to the test suite
    tcase_add_checked_fixture(tc_core, setup, teardown);
    tcase_add_test(tc_core, test_sbrk_allocation);
    suite_add_tcase(s, tc_core);

    return s;
}

// Main function
int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = sbrk_suite();
    sr = srunner_create(s);

    // Run the tests
    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? 0 : 1;
}