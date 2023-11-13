#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <vmpl/bitmap.h>

#include "benchmark.h"

#define BITMAP_SIZE 64

START_TEST(test_bitmap)
    size_t bitmap_size = 128;  // 可以设置为任意大小
    bitmap *b = bitmap_alloc(bitmap_size);
    ck_assert_ptr_ne(b, NULL);

    // 设置 bitmap 的第 10 位为 1
    bitmap_set(b, 10);

    // 检查 bitmap 的第 10 位是否为 1
    ck_assert(bitmap_test(b, 10));

    // 设置 bitmap 的第 10 位为 0
    bitmap_clear(b, 10);

    // 检查 bitmap 的第 10 位是否为 1
    ck_assert(!bitmap_test(b, 10));

    bitmap_free(b);
END_TEST

START_TEST(test_hbitmap)
    size_t hbitmap_size = 128;  // 可以设置为任意大小
    hbitmap *hb = hbitmap_alloc(hbitmap_size);
    ck_assert_ptr_ne(hb, NULL);

    // 设置 hbitmap 的第 10 位为 1
    hbitmap_set(hb, 10);

    // 检查 hbitmap 的第 10 位是否为 1
    ck_assert_int_eq(hbitmap_test(hb, 10), 1);

    // 清除 hbitmap 的第 10 位
    hbitmap_clear(hb, 10);

    // 检查 hbitmap 的第 10 位是否为 1
    ck_assert_int_eq(hbitmap_test(hb, 10), 0);

    hbitmap_free(hb);
END_TEST

START_TEST(test_bmap)
    size_t bmap_size = 128;  // 可以设置为任意大小
    bmap *bm = bmap_alloc(bmap_size, BITMAP_TYPE_HIERARCHICAL);
    ck_assert_ptr_ne(bm, NULL);

    // 设置 bmap 的第 10 位为 1
    bmap_set(bm, 10);

    // 检查 bmap 的第 10 位是否为 1
    ck_assert(bmap_test(bm, 10));

    // 设置 bmap 的第 10 位为 0
    bmap_clear(bm, 10);

    // 检查 bmap 的第 10 位是否为 1
    ck_assert(!bmap_test(bm, 10));

    bmap_free(bm);
END_TEST

Suite *bitmap_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("bitmap");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_bitmap);
    tcase_add_test(tc_core, test_hbitmap);
    tcase_add_test(tc_core, test_bmap);

    suite_add_tcase(s, tc_core);

    return s;
}