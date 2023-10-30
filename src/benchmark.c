// FILEPATH: /home/benshan/my-toy/test/src/benchmark.c
#define _GNU_SOURCE
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
#include <pthread.h> // pthread_create, pthread_join
#include <sched.h>
#ifdef USE_SECCOMP
#include <seccomp.h> /* libseccomp */
#endif
#include <sys/ipc.h> // shmget, shmctl, ftok, IPC_CREAT 
#include <sys/shm.h> // shmget, shmctl, shmat, shmdt
#include <sys/msg.h>
#include <sys/wait.h> // waitpid, WIFEXITED, WEXITSTATUS, WTERMSIG
#include <vmpl/sys.h> // read_cr0, read_cr2, read_cr3, read_cr4, read_rflags, rdmsr
#include <vmpl/apic.h>
#include <vmpl/vmpl.h>  // vmpl_enter, vmpl_server, vmpl_client
#include <vmpl/log.h> // log_init, log_set_level

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

int bind_cpu(int cpu)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_setaffinity");
        exit(1);
    }
    // rest of your code
    return 0;
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
        bind_cpu(THREAD_1_CORE);
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
            bind_cpu(THREAD_2_CORE);
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

    return 0;
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
    printf("DR0: 0x%lx\n", read_dr(0));
    printf("DR1: 0x%lx\n", read_dr(1));
    printf("DR2: 0x%lx\n", read_dr(2));
    printf("DR3: 0x%lx\n", read_dr(3));
    printf("DR6: 0x%lx\n", read_dr(6));
    printf("DR7: 0x%lx\n", read_dr(7));

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

int test_rdtsc(int argc, char *argv[])
{
	uint64_t overhead = ~0UL;
	int i;

	for (i = 0; i < N; i++) {
		uint64_t t0 = rdtsc();
		asm volatile("");
		uint64_t t1 = rdtscp();
		if (t1 - t0 < overhead)
			overhead = t1 - t0;
	}

    printf("rdtsc overhead: %lu cycles\n", overhead);
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

#define SHM_SIZE 1024

int tesh_shm(int argc, char *argv[])
{
    int shmid;
    key_t key;
    char *shm, *s;
    pid_t pid1, pid2;

    // 创建共享内存
    key = ftok(".", 's');
    shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0666);
    if (shmid < 0) {
        perror("shmget");
        exit(1);
    }

    // 创建子进程1
    pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        exit(1);
    } else if (pid1 == 0) {
        // 子进程1
        bind_cpu(THREAD_1_CORE);
        vmpl_enter(argc, argv);
        shm = shmat(shmid, NULL, 0);
        if (shm == (char *) -1) {
            perror("shmat");
            exit(1);
        }
        printf("shm: %p\n", shm);
        printf("Write to shm\n");
        for (s = shm; *s != '\0'; s++)
            putchar(*s);
        putchar('\n');
        *shm = '*';
        shmdt(shm);
        exit(0);
    }

    sleep(2); // Wait for child to start

    // 创建子进程2
    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        exit(1);
    } else if (pid2 == 0) {
        // 子进程2
        bind_cpu(THREAD_2_CORE);
        vmpl_enter(argc, argv);
        shm = shmat(shmid, NULL, 0);
        if (shm == (char *) -1) {
            perror("shmat");
            exit(1);
        }
        printf("shm: %p\n", shm);
        printf("Read from shm\n");
        for (s = shm; *s != '\0'; s++)
            putchar(*s);
        putchar('\n');
        *shm = '#';
        shmdt(shm);
        exit(0);
    }

    // 等待子进程结束
    waitpid(pid1, NULL, 0);
    waitpid(pid2, NULL, 0);

    // 删除共享内存
    shmctl(shmid, IPC_RMID, NULL);

    return 0;
}

#define MSG_SIZE 1024

struct msgbuf_t {
    long mtype;             /* message type, must be > 0 */
    char mtext[MSG_SIZE];   /* message data */
};

int test_msg(int argc, char *argv[])
{
    int msqid;
    key_t key;
    struct msgbuf_t buf;
    pid_t pid1, pid2;

    // 创建消息队列
    key = ftok(".", 'm');
    msqid = msgget(key, IPC_CREAT | 0666);
    if (msqid < 0) {
        perror("msgget");
        exit(1);
    }

    // 创建子进程1
    pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        exit(1);
    } else if (pid1 == 0) {
        // 子进程1
        bind_cpu(THREAD_1_CORE);
        vmpl_enter(argc, argv);
        if (msgrcv(msqid, &buf, MSG_SIZE, 1, 0) < 0) {
            perror("msgrcv");
            exit(1);
        }
        printf("Received message: %s\n", buf.mtext);
        exit(0);
    }

    sleep(2); // Wait for child to start

    // 创建子进程2
    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        exit(1);
    } else if (pid2 == 0) {
        // 子进程2
        bind_cpu(THREAD_2_CORE);
        vmpl_enter(argc, argv);
        buf.mtype = 1;
        sprintf(buf.mtext, "Hello, world!");
        if (msgsnd(msqid, &buf, sizeof(buf.mtext), IPC_NOWAIT) < 0) {
            perror("msgsnd");
            exit(1);
        }
        exit(0);
    }

    // 等待子进程结束
    waitpid(pid1, NULL, 0);
    waitpid(pid2, NULL, 0);

    // 删除消息队列
    msgctl(msqid, IPC_RMID, NULL);

    return 0;
}

int test_fork(int argc, char *argv[])
{
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        printf("Child process\n");
        exit(EXIT_SUCCESS);
    } else {
        // Parent process
        printf("Parent process\n");
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else {
            printf("Child exited with signal %d\n", WTERMSIG(status));
        }
    }

    return 0;
}

int test_vfork(int argc, char *argv[])
{
    pid_t pid = vfork();
    if (pid == -1) {
        perror("vfork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        printf("Child process\n");
        exit(EXIT_SUCCESS);
    } else {
        // Parent process
        printf("Parent process\n");
        int status;
        waitpid(pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Child exited with status %d\n", WEXITSTATUS(status));
        } else {
            printf("Child exited with signal %d\n", WTERMSIG(status));
        }
    }

    return 0;
}

void *thread_func(void *arg)
{
    printf("Hello from thread\n");
    return NULL;
}

int test_pthread(int argc, char *argv[])
{
    pthread_t thread;
    printf("Hello from main thread\n");
    int ret = pthread_create(&thread, NULL, thread_func, NULL);
    if (ret != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }
    pthread_join(thread, NULL);
    printf("Joined thread\n");
    return 0;
}

#ifdef USE_SECCOMP
int test_seccomp(int argc, char *argv[])
{
    printf("step 1: unrestricted\n");

    // Init the filter
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

    // setup basic whitelist
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

    // setup our rule
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2,
                        SCMP_A0(SCMP_CMP_EQ, 1),
                        SCMP_A1(SCMP_CMP_EQ, 2));

    // build and load the filter
    seccomp_load(ctx);
    printf("step 2: only 'write' and dup2(1, 2) syscalls\n");

    // Redirect stderr to stdout
    dup2(1, 2);
    printf("step 3: stderr redirected to stdout\n");

    // Duplicate stderr to arbitrary fd
    dup2(2, 42);
    printf("step 4: !! YOU SHOULD NOT SEE ME !!\n");

    // Success (well, not so in this case...)
    return 0;
}
#endif

void run_test(Test *test, int argc, char *argv[]) {
    printf("Running test %s...\n", test->name);
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
    {"test_rdtsc", test_rdtsc, vmpl_enter},
    {"test_time", test_time, vmpl_enter},
    {"test_sys", test_sys, vmpl_enter},
    {"test_prctl", test_prctl, vmpl_enter},
    {"test_debug", test_debug, vmpl_enter},
    {"test_syscall", test_syscall, vmpl_enter},
    {"test_mmap", test_mmap, vmpl_enter},
    {"test_munmap", test_munmap, vmpl_enter},
    {"test_mprotect", test_mprotect, vmpl_enter},
    {"test_shm", tesh_shm, NULL},
    {"test_msg", test_msg, NULL},
    {"test_signal", test_signal, vmpl_enter},
    {"test_vdso", test_vdso, vmpl_enter},
    {"test_fork", test_fork, vmpl_enter},
    {"test_vfork", test_vfork, vmpl_enter},
    {"test_pthread", test_pthread, vmpl_enter},
#ifdef USE_SECCOMP
    {"test_seccomp", test_seccomp, vmpl_enter},
#endif
    {"vmpl_server", vmpl_server, vmpl_enter},
    {"vmpl_client", vmpl_client, vmpl_enter},
    {"bench_dune_ring", bench_dune_ring, vmpl_enter},
};

#define num_tests (sizeof(tests) / sizeof(Test))

struct test_args {
    char *test_name;
    int run_all;
    int list_tests;
    int show_help;
    int show_maps;
    int log_level;
};

void print_proc_self_maps() {
    char command[100];
    printf("proc/self/maps:\n");
    sprintf(command, "cat /proc/%d/maps", getpid());
    system(command);
}

#ifdef HAVE_ARGP
#include <argp.h>

static struct argp_option options[] = {
    // define options
    {"all-tests", 'a', 0, 0, "Run all tests", 1},
    {"test-name", 't', "TEST_NAME", 0, "Run a specific test", 1},
    {"list-tests", 'l', 0, 0, "List all tests", 1},
    {"help", 'h', 0, 0, "Show help", 1},
    {"show-maps", 'm', 0, 0, "Show /proc/self/maps", 1},
    {"log-level", 'v', "LOG_LEVEL", 0, "Set log level", 1},
    {0}
};

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
    // parse options
    struct test_args *args = state->input;
    switch (key) {
        case 'a':
            args->run_all = 1;
            break;
        case 't':
            args->test_name = arg;
            break;
        case 'l':
            args->list_tests = 1;
            break;
        case 'h':
            args->show_help = 1;
            break;
        case 'm':
            args->show_maps = 1;
            break;
        case 'v':
            args->log_level = atoi(arg);
            break;
        case ARGP_KEY_ARG:
            argp_usage(state);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt};

static int parse_args(int argc, char *argv[], struct test_args *args) {
    argp_parse(&argp, argc, argv, 0, 0, args);
    return 0;
}
#else
static void usage(const char *program_name) {
    printf("Usage: %s [-a] [-t test_name] [-l] [-h] [-m] [-v log_level]\n", program_name);
}

static int parse_args(int argc, char *argv[], struct test_args *args) {
    int opt;
    while ((opt = getopt(argc, argv, "alt:hmv:")) != -1) {
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
            case 'm':
                args->show_maps = 1;
                break;
            case 'v':
                args->log_level = atoi(optarg);
                break;
            case '?':
                usage(argv[0]);
                return 1;
        }
    }

    return 0;
}
#endif

int main(int argc, char** argv)
{
    struct test_args args = {
        .test_name = NULL,
        .run_all = 0,
        .list_tests = 0,
        .show_help = 0,
        .show_maps = 0,
        .log_level = LOG_LEVEL_INFO,
    };
    
    if (parse_args(argc, argv, &args) != 0) {
        return 1;
    }

    if (args.log_level >= LOG_LEVEL_TRACE 
        && args.log_level <= LOG_LEVEL_ERROR) {
        set_log_level(args.log_level);
    } else {
        printf("Invalid log level %d\n", args.log_level);
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

    if (args.show_maps)
        print_proc_self_maps();

    if (args.run_all) {
        for (int i = 0; i < num_tests; i++) {
            run_test(&tests[i], argc, argv);
        }
        return 0;
    } else if (args.test_name != NULL) {
        for (int i = 0; i < num_tests; i++) {
            if (strstr(args.test_name, tests[i].name) != NULL) {
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