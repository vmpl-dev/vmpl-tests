#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define XSAVE_SIZE 4096
char buffer[XSAVE_SIZE];

int main() {
    unsigned long long mask = 0x3;

    char *buffer = memalign(64, XSAVE_SIZE);
    memset(buffer, 0, XSAVE_SIZE);

    // save the buffer
    asm volatile (
        ".byte 0x48, 0x0f, 0xae, 0x27"
        :
        : "D" (buffer), "a" (mask), "d" (0x00)
        : "memory"
    );

    printf("XSAVE buffer: ");
    for (int i = 0; i < XSAVE_SIZE; i++) {
        printf("%02x ", (unsigned char)buffer[i]);
    }
    printf("\n");

    // restore the buffer
    asm volatile (
        ".byte 0x48, 0x0f, 0xae, 0x2f"
        :
        : "D" (buffer), "a" (mask), "d" (0x00)
        : "memory"
    );

    free(buffer);

    return 0;
}