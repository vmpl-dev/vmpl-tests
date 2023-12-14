#include <stdlib.h>
#include <stdio.h>

#define XSAVE_SIZE 4096
#define XCR_XFEATURE_ENABLED_MASK 0x00000000

unsigned long long xsave_area[XSAVE_SIZE / sizeof(unsigned long long)];

void save_state() {
    unsigned long long mask = 0x07; // Save x87, SSE, and AVX registers

    asm volatile (
        ".byte 0x48, 0x0f, 0xae, 0x27" // xsave instruction
        :
        : "D" (xsave_area), "a" (mask), "d" (0x00)
        : "memory"
    );
}

void restore_state() {
    unsigned long long mask = 0x07; // Restore x87, SSE, and AVX registers

    asm volatile (
        ".byte 0x48, 0x0f, 0xae, 0x2f" // xrstor instruction
        :
        : "D" (xsave_area), "a" (mask), "d" (0x00)
        : "memory"
    );
}

int main() {
    save_state();
    // Do some work here...
    restore_state();

    return 0;
}