#include "benchmark.h"

Suite *misc_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Miscellaneous");

    /* Core test case */
    tc_core = tcase_create("Misc");

    suite_add_tcase(s, tc_core);

    return s;
}