#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "globals.h"
#include "vmpl.h"
#include "svsm-vmpl.h"
#ifdef USE_GLIBC
#include "hypercall.h"
#include "utils.h"
#include "args.h"
#else
#include <sys/mman.h>
#include <sys/resource.h>
#endif

static char line[1024];

int main(int argc, char *argv[])
{
#ifdef USE_GLIBC
    struct arguments arguments;

    arguments.init = 0;
    arguments.enter = 0;

    parse_args(argc, argv, &arguments);
    if (arguments.enter) {
        vmpl_enter(argc, argv);
    }
#else
    vmpl_enter(argc, argv);
#endif
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