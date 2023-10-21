#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "globals.h"
#include "vmpl.h"
#include "procmap.h"
#include "svsm-vmpl.h"
#include "hypercall.h"
#include "utils.h"
#include "args.h"

static char line[1024];

int main(int argc, char *argv[])
{
    struct arguments arguments;

    arguments.init = 0;
    arguments.enter = 0;

    parse_args(argc, argv, &arguments);
    if (arguments.enter) {
        vmpl_enter(argc, argv);
    }

    hp_write(STDOUT_FILENO, "vmpl-process: hello world!\n", 27);

    int fd;
    ssize_t num_read;
    fd = hp_open("/proc/self/maps", O_RDONLY, 0);
    if (fd == -1) {
        hp_exit();
    }

    while ((num_read = hp_read(fd, line, 1024)) > 0) {
        ssize_t num_written = hp_write(STDOUT_FILENO, line, num_read);
        if (num_written != num_read) {
            hp_exit();
        }
    }

    if (num_read == -1) {
        hp_exit();
    }

    if (hp_close(fd) == -1) {
        hp_exit();
    }

#if 0
    vmpl_printf("vmpl-process: num-args = %d", argc);
#endif

    hp_exit();

    return 0;
}