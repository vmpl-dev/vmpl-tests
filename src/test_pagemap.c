#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

#define PAGE_SHIFT 12
#define PAGEMAP_LENGTH 8

int mem_fd;
void *pagemap;

int virt_to_phys(void *virt_addr, uint64_t *phys_addr) {
    uint64_t virt_pfn = (uint64_t)virt_addr >> PAGE_SHIFT;
    size_t nbyte, offset = virt_pfn * PAGEMAP_LENGTH;

    lseek(mem_fd, offset, SEEK_SET);
    nbyte = read(mem_fd, &pagemap, PAGEMAP_LENGTH);

    if(nbyte != PAGEMAP_LENGTH) {
        return -1;
    }

    // Check if page is present
    if(!((uint64_t)pagemap & 0x7fffffffffffffULL)) {
        return -1;
    }

    *phys_addr = ((uint64_t)pagemap & 0x7fffffffffffffULL) << PAGE_SHIFT;
    return 0;
}

int main() {
    void *virt_addr = malloc(1024);
    uint64_t phys_addr;

    mem_fd = open("/proc/self/pagemap", O_RDONLY);
    if(mem_fd < 0) {
        perror("open pagemap");
        return -1;
    }

    if(virt_to_phys(virt_addr, &phys_addr)) {
        printf("Error getting physical address\n");
    } else {
        printf("Virtual addr: %p Physical addr: %llx\n", virt_addr, (long long unsigned int)phys_addr);
    }

    free(virt_addr);
    close(mem_fd);

    return 0;
}