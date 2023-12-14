#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#define SIZE_256MB (256 * 1024 * 1024)

int main() {
    void *addr = mmap(NULL, SIZE_256MB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    printf("mmap returned address: %p\n", addr);

    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (!maps_file) {
        perror("fopen failed");
        return 1;
    }

    char line[256];
    while (fgets(line, sizeof(line), maps_file)) {
        printf("%s", line);
    }

    fclose(maps_file);
    munmap(addr, SIZE_256MB);

    return 0;
}