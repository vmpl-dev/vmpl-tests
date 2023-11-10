#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <vmpl/bitmap.h>

#include "benchmark.h"

#define BITMAP_SIZE 64

int test_bitmap(int argc, char *argv[]) {
    size_t bitmap_size = 128;  // 可以设置为任意大小
    bitmap *b = bitmap_alloc(bitmap_size);

    if (!b) {
        printf("Failed to allocate bitmap\n");
        return -1;
    }

    // 设置 bitmap 的第 10 位为 1
    bitmap_set(b, 10);

    // 检查 bitmap 的第 10 位是否为 1
    if (bitmap_test(b, 10)) {
        printf("Bit 10 is set\n");
    } else {
        printf("Bit 10 is not set\n");
    }

    // 清除 bitmap 的第 10 位
    bitmap_clear(b, 10);

    // 检查 bitmap 的第 10 位是否为 1
    if (bitmap_test(b, 10)) {
        printf("Bit 10 is set\n");
    } else {
        printf("Bit 10 is not set\n");
    }

    bitmap_free(b);

    return 0;
}

int test_hbitmap(int argc, char *argv[]) {
    size_t hbitmap_size = 128;  // 可以设置为任意大小
    hbitmap *hb = hbitmap_alloc(hbitmap_size);

    if (!hb) {
        printf("Failed to allocate hbitmap\n");
        return -1;
    }

    // 设置 hbitmap 的第 10 位为 1
    hbitmap_set(hb, 10);

    // 检查 hbitmap 的第 10 位是否为 1
    if (hbitmap_test(hb, 10)) {
        printf("Bit 10 is set\n");
    } else {
        printf("Bit 10 is not set\n");
    }

    // 清除 hbitmap 的第 10 位
    hbitmap_clear(hb, 10);

    // 检查 hbitmap 的第 10 位是否为 1
    if (hbitmap_test(hb, 10)) {
        printf("Bit 10 is set\n");
    } else {
        printf("Bit 10 is not set\n");
    }

    hbitmap_free(hb);

    return 0;
}

int test_bmap(int argc, char *argv[]) {
    size_t bmap_size = 128;  // 可以设置为任意大小
    bmap *bm = bmap_alloc(bmap_size, BITMAP_TYPE_HIERARCHICAL);

    if (!bm) {
        printf("Failed to allocate bmap\n");
        return -1;
    }

    // 设置 bmap 的第 10 位为 1
    bmap_set(bm, 10);

    // 检查 bmap 的第 10 位是否为 1
    if (bmap_test(bm, 10)) {
        printf("Bit 10 is set\n");
    } else {
        printf("Bit 10 is not set\n");
    }

    // 清除 bmap 的第 10 位
    bmap_clear(bm, 10);

    // 检查 bmap 的第 10 位是否为 1
    if (bmap_test(bm, 10)) {
        printf("Bit 10 is set\n");
    } else {
        printf("Bit 10 is not set\n");
    }

    bmap_free(bm);

    return 0;
}