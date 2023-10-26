#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#ifndef __GLIBC__
#include <sys/mman.h>
#include <sys/resource.h>
#endif

#include "sys.h"
#include "vmpl.h"
static char line[1024];

int main(int argc, char *argv[])
{
    VMPL_ENTER;
    printf("vmpl-process: hello world!\n");

    int fd;
    ssize_t num_read;
    fd = open("/proc/self/maps", O_RDONLY, 0);
    if (fd == -1) {
        exit(EXIT_FAILURE);
    }

    while ((num_read = read(fd, line, 1024)) > 0) {
        ssize_t num_written = write(STDOUT_FILENO, line, num_read);
        if (num_written != num_read) {
            perror("vmpl-process: write");
            exit(EXIT_FAILURE);
        }
    }

    if (num_read == -1) {
        perror("vmpl-process: read");
        exit(EXIT_FAILURE);
    }

    if (close(fd) == -1) {
        perror("vmpl-process: close");
        exit(EXIT_FAILURE);
    }

    printf("vmpl-process: num-args = %d\n", argc);

    exit(EXIT_SUCCESS);

    return 0;
}