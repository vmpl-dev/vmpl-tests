// FILEPATH: /home/benshan/my-toy/test/src/benchmark.c
#include <stdio.h>
#include <stdlib.h> // malloc
#include <string.h> // strcmp ..
#include <stdbool.h> // bool false true
#include <stdlib.h> // sort
#include <limits.h> // INT_MAX
#include <math.h> // sqrt
#include <unistd.h> // sleep
#include <assert.h> // assert
#include <fcntl.h> // open
#include <signal.h> // signal
#include <syscall.h> // SYS_clock_gettime
#include <sys/mman.h> // mmap
#include <sys/prctl.h> // arch_prctl
#include <sys/types.h> // open
#include <sys/stat.h> // open
#include <vmpl/sys.h>
#include <vmpl/vmpl.h>

#include "benchmark.h"

typedef int (*Func)(int argc, char *argv[]);

typedef struct {
    const char *name;
    Func exec_func;
    Func prolog;
} Test;

static char line[1024];

static uint64_t get_time(void)
{
    struct timespec ts;
    syscall(SYS_clock_gettime, CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

void handle_sigint(int sig)
{
    printf("Caught signal %d\n", sig);
  	exit(0);
}

int vmpl_process(int argc, char *argv[])
{
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

int test_socket(int argc, char *argv[]) {
    pid_t server_pid = fork();
    if (server_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (server_pid == 0) {
        // Child process
        vmpl_enter(argc, argv);
        return vmpl_server(argc, argv);
    } else {
        // Parent process
        sleep(2); // Wait for server to start
        pid_t client_pid = fork();
        if (client_pid == -1) {
            perror("fork");
            kill(server_pid, SIGTERM);
            exit(EXIT_FAILURE);
        } else if (client_pid == 0) {
            // Child process
            vmpl_enter(argc, argv);
            return vmpl_client(argc, argv);
        } else {
            // Parent process
            int status;
            waitpid(client_pid, &status, 0);
            if (WIFEXITED(status)) {
                printf("Client exited with status %d\n", WEXITSTATUS(status));
            } else {
                printf("Client exited with signal %d\n", WTERMSIG(status));
            }
            waitpid(server_pid, &status, 0);
            if (WIFEXITED(status)) {
                printf("Server exited with status %d\n", WEXITSTATUS(status));
            } else {
                printf("Server exited with signal %d\n", WTERMSIG(status));
            }
        }
    }

    return 0;
}

int test_sys(int argc, char *argv[])
{
    printf("vmpl-process: hello world!\n");

    size_t cr0, cr2, cr3, cr4, efer, rflags;
    cr0 = read_cr0();
    cr2 = read_cr2();
    cr3 = read_cr3();
    cr4 = read_cr4();
    efer = rdmsr(MSR_EFER);
    rflags = read_rflags();
    printf("vmpl-process: cr0 = 0x%lx, cr2 = 0x%lx, cr3 = 0x%lx\n", cr0, cr2, cr3);
    printf("vmpl-process: cr4 = 0x%lx, efer = 0x%lx, rflags = 0x%lx\n", cr4, efer, rflags);
}

int test_vdso(int argc, char *argv[])
{
    printf("hello\n");
    int a = getpid();
    int b;
    while ((b = getpid()) == a) {
        printf("continue\n");
    }
    printf("we failed  %d %d\n", a, b);
    return 0;
}

int test_signal(int argc, char *argv[])
{
    signal(SIGINT, handle_sigint);

    while (true);

    return 0;
}

int test_debug(int argc, char *argv[])
{
    // 读取DR0-DR7的值并打印
    printf("DR0: 0x%llx\n", read_dr(0));
    printf("DR1: 0x%llx\n", read_dr(1));
    printf("DR2: 0x%llx\n", read_dr(2));
    printf("DR3: 0x%llx\n", read_dr(3));
    printf("DR6: 0x%llx\n", read_dr(6));
    printf("DR7: 0x%llx\n", read_dr(7));

    return 0;
}

int test_prctl(int argc, char *argv[])
{
    unsigned long fs_reg_value;
    unsigned long gs_reg_value;

    int ret_fs = arch_prctl(ARCH_GET_FS, &fs_reg_value);
    int ret_gs = arch_prctl(ARCH_GET_GS, &gs_reg_value);

    if (ret_fs == 0) {
        printf("FS segment register value: 0x%lx\n", fs_reg_value);
    } else {
        printf("Failed to get FS segment register value\n");
    }

    if (ret_gs == 0) {
        printf("GS segment register value: 0x%lx\n", gs_reg_value);
    } else {
        printf("Failed to get GS segment register value\n");
    }

    return 0;
}

int test_syscall(int argc, char *argv[])
{
    int fd = open("/dev/zero", O_RDONLY);
    printf("fd: %d\n", fd);
    close(fd);
    return 0;
}

int test_time(int argc, char *argv[])
{
    pid_t pid;
    uint64_t start_time;
    uint64_t end_time;
    uint64_t total_time = 0;

    start_time = get_time();
    end_time = get_time();

    printf("Elapsed time: %lu ns\n", end_time - start_time);

    for (int i = 0; i < NUM_ITERATIONS; i++)
    {
        start_time = rdtsc();
        pid = getpid();
        end_time = rdtsc();
        total_time += end_time - start_time;
    }

    printf("Average time: %lu cycles\n", total_time / NUM_ITERATIONS);

    return 0;
}

int test_mmap(int argc, char *argv[])
{
    int fd = open("/dev/zero", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    printf("addr: %p\n", addr);
    close(fd);
    return 0;
}

int test_mprotect(int argc, char *argv[])
{
    int fd = open("/dev/zero", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    printf("addr: %p\n", addr);
    mprotect(addr, 4096, PROT_READ | PROT_WRITE);
    close(fd);
    return 0;
}

int test_munmap(int argc, char *argv[])
{
    int fd = open("/dev/zero", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    printf("addr: %p\n", addr);
    munmap(addr, 4096);
    close(fd);
    return 0;
}

void run_test(Test *test, int argc, char *argv[]) {
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        if (test->prolog != NULL)
            test->prolog(argc, argv);
        int ret = test->exec_func(argc, argv);
        exit(ret);
    } else {
        // Parent process
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            int ret = WEXITSTATUS(status);
            if (ret == 0) {
                printf(COLOR_GREEN "Test %s passed\n" COLOR_RESET, test->name);
            } else {
                printf(COLOR_RED "Test %s failed with exit code %d\n" COLOR_RESET, test->name, ret);
            }
        } else {
            printf(COLOR_RED "Test %s failed with signal %d\n" COLOR_RESET, test->name, WTERMSIG(status));
        }
    }
}

static Test tests[] = {
    {"test_process", vmpl_process, vmpl_enter},
    {"test_socket", test_socket, NULL},
    {"test_time", test_time, vmpl_enter},
    {"test_sys", test_sys, vmpl_enter},
    {"test_prctl", test_prctl, vmpl_enter},
    {"test_debug", test_debug, vmpl_enter},
    {"test_syscall", test_syscall, vmpl_enter},
    {"test_mmap", test_mmap, vmpl_enter},
    {"test_munmap", test_munmap, vmpl_enter},
    {"test_mprotect", test_mprotect, vmpl_enter},
    {"test_signal", test_signal, vmpl_enter},
    {"test_vdso", test_vdso, vmpl_enter},
};

#define num_tests (sizeof(tests) / sizeof(Test))

struct test_args {
    char *test_name;
    int run_all;
    int list_tests;
    int show_help;
};

static void usage(const char *program_name) {
    printf("Usage: %s [-a] [-t test_name] [-l] [-h]\n", program_name);
}

static int parse_args(int argc, char *argv[], struct test_args *args) {
    int opt;
    while ((opt = getopt(argc, argv, "alt:h")) != -1) {
        switch (opt) {
            case 'a':
                args->run_all = 1;
                break;
            case 't':
                args->test_name = optarg;
                break;
            case 'l':
                args->list_tests = 1;
                break;
            case 'h':
                args->show_help = 1;
                break;
            case '?':
                usage(argv[0]);
                return 1;
        }
    }

    return 0;
}

int main(int argc, char** argv)
{
    struct test_args args = {
        .test_name = NULL,
        .run_all = 0,
        .list_tests = 0,
        .show_help = 0
    };
    
    if (parse_args(argc, argv, &args) != 0) {
        return 1;
    }

    if (args.show_help) {
        usage(argv[0]);
        return 0;
    }

    if (args.list_tests) {
        printf("Supported tests:\n");
        for (int i = 0; i < num_tests; i++) {
            printf("  %s\n", tests[i].name);
        }
        return 0;
    }

    if (args.run_all) {
        for (int i = 0; i < num_tests; i++) {
            printf("Running test %s...\n", tests[i].name);
            run_test(&tests[i], argc, argv);
        }
        return 0;
    } else if (args.test_name != NULL) {
        for (int i = 0; i < num_tests; i++) {
            if (strstr(args.test_name, tests[i].name) != NULL) {
                printf("Running test %s...\n", tests[i].name);
                run_test(&tests[i], argc, argv);
                return 0;
            }
        }
        printf("Test %s not found\n", args.test_name);
        return 1;
    } else {
        usage(argv[0]);
        return 1;
    }

    return 0;
}