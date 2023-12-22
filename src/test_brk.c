#include <stdio.h>
#include <unistd.h>

int main() {
    // 获取当前的程序 break
    void *current_brk = sbrk(0);
    if (current_brk == (void *)-1) {
        perror("sbrk");
        return 1;
    }

    // 使用 brk 分配 4KB 内存
    void *new_brk = (char *)current_brk + 4096;
    if (brk(new_brk) == -1) {
        perror("brk");
        return 1;
    }

    // 写入内存
    char *buf = (char *)current_brk;
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

    return 0;
}