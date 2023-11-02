#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

#include "benchmark.h"

#define BITMAP_SIZE 64

uint64_t *bitmap_alloc(size_t size) {
    return calloc(size / 64, sizeof(uint64_t));
}

void bitmap_set(uint64_t *bitmap, int bit) {
    bitmap[bit / 64] |= (1ULL << (bit % 64));
}

int bitmap_test(const uint64_t *bitmap, int bit) {
    return (bitmap[bit / 64] & (1ULL << (bit % 64))) != 0;
}

void bitmap_clear(uint64_t *bitmap, int bit) {
    bitmap[bit / 64] &= ~(1ULL << (bit % 64));
}

int test_bitmap(int argc, char const *argv[]) {
    size_t bitmap_size = 128;  // 可以设置为任意大小
    uint64_t *bitmap = bitmap_alloc(bitmap_size);

    if (!bitmap) {
        printf("Failed to allocate bitmap\n");
        return -1;
    }

    // 设置 bitmap 的第 10 位为 1
    bitmap_set(bitmap, 10);

    // 检查 bitmap 的第 10 位是否为 1
    if (bitmap_test(bitmap, 10)) {
        printf("Bit 10 is set\n");
    } else {
        printf("Bit 10 is not set\n");
    }

    // 清除 bitmap 的第 10 位
    bitmap_clear(bitmap, 10);

    // 检查 bitmap 的第 10 位是否为 1
    if (bitmap_test(bitmap, 10)) {
        printf("Bit 10 is set\n");
    } else {
        printf("Bit 10 is not set\n");
    }

    free(bitmap);

    return 0;
}