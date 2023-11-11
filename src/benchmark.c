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
#include <sys/mman.h> // mmap
#include <sys/prctl.h> // arch_prctl
#include <sys/types.h> // open
#include <sys/stat.h> // open
#include <sys/time.h> // gettimeofday
#include <time.h> // time
#include <pthread.h> // pthread_create, pthread_join
#include <sched.h>
#ifdef HAVE_SECCOMP
#include <seccomp.h> /* libseccomp */
#endif
#ifdef __GLIBC__
#include <sys/ipc.h> // shmget, shmctl, ftok, IPC_CREAT 
#include <sys/sem.h> // semget, semctl, semop
#include <sys/shm.h> // shmget, shmctl, shmat, shmdt
#else
#include <sys/msg.h>
#include <sys/wait.h> // waitpid, WIFEXITED, WEXITSTATUS, WTERMSIG
#include <semaphore.h>
#endif
#include <vmpl/sys.h> // read_cr0, read_cr2, read_cr3, read_cr4, read_rflags, rdmsr
#include <vmpl/apic.h>
#include <vmpl/vmpl.h>  // vmpl_enter, vmpl_server, vmpl_client
#include <vmpl/seimi.h> // sa_alloc, sa_free
#include <vmpl/log.h> // log_init, log_set_level
#include <vmpl/mm.h>

#include "benchmark.h"

typedef int (*Func)(int argc, char *argv[]);

typedef struct {
    const char *name;
    Func exec_func;
    Func prolog;
} Test;

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
    static char line[1024];
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
        VMPL_ENTER;
        return vmpl_server(argc, argv);
    } else {
        // Parent process
        sleep(SLEEP_TIME); // Wait for server to start
        pid_t client_pid = fork();
        if (client_pid == -1) {
            perror("fork");
            kill(server_pid, SIGTERM);
            exit(EXIT_FAILURE);
        } else if (client_pid == 0) {
            // Child process
            bind_cpu(THREAD_2_CORE);
            VMPL_ENTER;
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

static void vc_handler(struct dune_tf *tf)
{
    printf("vc_handler: received VMM communication\n");
    exit(EXIT_SUCCESS);
}

int test_cpuid(int argc, char *argv[])
{
    unsigned int eax, ebx, ecx, edx;

    dune_register_intr_handler(T_VC, vc_handler);

    eax = 0x80000008; // Get virtual and physical address sizes
    __asm__ volatile(
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(eax)
    );

    printf("Physical address size: %u bits\n", eax & 0xFF);
    printf("Virtual address size: %u bits\n", (eax >> 8) & 0xFF);

    return 0;
}

int test_vsyscall(int argc, char *argv[])
{
    struct timeval tv;
    struct timezone tz;
    time_t t;

    /* 测试 gettimeofday 函数 */
    printf("test gettimeofday\n");
    if (gettimeofday(&tv, &tz) == 0)
        printf("gettimeofday: %ld.%06ld\n", (long)tv.tv_sec, (long)tv.tv_usec);
    else
        perror("gettimeofday");

    /* 测试 time 函数 */
    printf("test time\n");
    t = time(NULL);
    if (t != (time_t)-1)
        printf("time: %ld\n", (long)t);
    else
        perror("time");

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

    start_time = rdtsc();
    for (int i = 0; i < NUM_ITERATIONS; i++)
    {
        pid = getpid();
    }
    end_time = rdtsc();
    total_time = end_time - start_time;

    printf("Average time: %lu cycles\n", total_time / NUM_ITERATIONS);
    return 0;
}

int test_mmap(int argc, char *argv[])
{
    int fd = open("/dev/zero", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
        exit(EXIT_FAILURE);
    } else {
        printf("mmap: %p\n", addr);
        close(fd);
        exit(EXIT_SUCCESS);
    }
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

int test_seimi(int argc, char *argv[])
{
    int cr4;
    char *seimi_user;

    // Allocate 4096 bytes of memory
    seimi_user = sa_alloc(4096, false, NULL);
    sprintf(seimi_user, "Hello, world!");

    // Print the address of seimi_user
    printf("seimi_user: %s\n", seimi_user);

    // Now, we enter VMPL mode
    VMPL_ENTER;
    printf("seimi_user[vmpl]: %p\n", seimi_user);

    // Read CR4
    cr4 = read_cr4();
    printf("SMAP: %s\n", cr4 & CR4_SMAP ? "enabled" : "disabled");

    // Write to seimi_user (protected)
    __asm__ volatile("stac\n");
    sprintf(seimi_user, "Hello, SEIMI!");
    printf("seimi_user: %s\n", seimi_user);
    __asm__ volatile("clac\n");

    sa_free(seimi_user, 4096);
    return 0;
}

int test_seimi_ro(int argc, char *argv[])
{
    char *seimi_user, *seimi_super;
    long offset;

    // Allocate 4096 bytes of memory
    seimi_user = sa_alloc(4096, true, &offset);
    seimi_super = seimi_user + offset;
    sprintf(seimi_user, "Hello, world!");

    // Print the addresses of seimi_user and seimi_super
    printf("seimi_user: %s\n", seimi_user);
    printf("seimi_super: %s\n", seimi_super);
    printf("offset: %lx\n", offset);

    // Now, we enter VMPL mode
    VMPL_ENTER;
    printf("seimi_user[vmpl]: %p\n", seimi_user);
    printf("seimi_super[vmpl]: %p\n", seimi_super);

    // Write to seimi_user (protected)
    __asm__ volatile("stac\n");
    sprintf(seimi_user, "Hello, SEIMI!");
    printf("seimi_user: %s\n", seimi_user);
    __asm__ volatile("clac\n");

    // Read from seimi_super (read-only)
    printf("seimi_super: %s\n", seimi_super);

    sa_free(seimi_user, 4096);

    return 0;
}

int test_sbrk() {
    void *cur_brk, *tmp_brk = NULL;

    printf("The original program break: %p\n", sbrk(0));

    tmp_brk = sbrk(4096);
    if (tmp_brk == (void *)-1) {
        printf("ERROR: sbrk failed. Exiting...\n");
        return -1;
    }

    cur_brk = sbrk(0);
    printf("The program break after incrementing: %p\n", cur_brk);

    tmp_brk = sbrk(-4096);
    if (tmp_brk == (void *)-1) {
        printf("ERROR: sbrk failed. Exiting...\n");
        return -1;
    }

    cur_brk = sbrk(0);
    printf("The program break after decrementing: %p\n", cur_brk);

    return 0;
}

sem_t sem;

void* sem_thread_func(void* arg) {
    bind_cpu(THREAD_1_CORE);
    VMPL_ENTER;
    printf("Thread waiting on semaphore...\n");
    sem_wait(&sem);
    printf("Thread got semaphore!\n");
    return NULL;
}

void* sem_post_func(void* arg) {
    bind_cpu(THREAD_2_CORE);
    VMPL_ENTER;
    sleep(SLEEP_TIME);
    printf("Posting to semaphore...\n");
    sem_post(&sem);
    return NULL;
}

int test_sem(void) {
    pthread_t thread1, thread2;

    printf("Initializing semaphore...\n");
    sem_init(&sem, 0, 0);

    printf("Creating threads...\n");
    pthread_create(&thread1, NULL, sem_thread_func, NULL);
    pthread_create(&thread2, NULL, sem_post_func, NULL);

    printf("Waiting for threads to finish...\n");
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Destroying semaphore...\n");
    sem_destroy(&sem);

    printf("Done!\n");
    return 0;
}

int test_pipe() {
    int pipefd[2];
    pid_t cpid;
    char buf;

    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    cpid = fork();
    if (cpid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (cpid == 0) {    /* Child reads from pipe */
        VMPL_ENTER;
        close(pipefd[1]);          /* Close unused write end */

        while (read(pipefd[0], &buf, 1) > 0)
            write(STDOUT_FILENO, &buf, 1);

        write(STDOUT_FILENO, "\n", 1);
        close(pipefd[0]);
        _exit(EXIT_SUCCESS);

    } else {            /* Parent writes argv[1] to pipe */
        VMPL_ENTER;
        close(pipefd[0]);          /* Close unused read end */
        write(pipefd[1], "test", 4);
        close(pipefd[1]);          /* Reader will see EOF */
        wait(NULL);                /* Wait for child */
        exit(EXIT_SUCCESS);
    }
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
        VMPL_ENTER;
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

    sleep(SLEEP_TIME); // Wait for child to start

    // 创建子进程2
    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        exit(1);
    } else if (pid2 == 0) {
        // 子进程2
        bind_cpu(THREAD_2_CORE);
        VMPL_ENTER;
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
        VMPL_ENTER;
        if (msgrcv(msqid, &buf, MSG_SIZE, 1, 0) < 0) {
            perror("msgrcv");
            exit(1);
        }
        printf("Received message: %s\n", buf.mtext);
        exit(0);
    }

    sleep(SLEEP_TIME); // Wait for child to start

    // 创建子进程2
    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        exit(1);
    } else if (pid2 == 0) {
        // 子进程2
        bind_cpu(THREAD_2_CORE);
        VMPL_ENTER;
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
    /* vfork syscall cannot be made from C code */
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
    int argc = *(int *)arg;
    printf("Hello from thread\n");
    printf("argc: %d\n", argc);
    return NULL;
}

int test_pthread(int argc, char *argv[])
{
    pthread_t thread;
    pthread_attr_t attr;
    printf("Hello from main thread\n");
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    int ret = pthread_create(&thread, &attr, thread_func, &argc);
    if (ret != 0) {
        perror("pthread_create");
        exit(EXIT_FAILURE);
    }
    pthread_join(thread, NULL);
    printf("Joined thread\n");
    return 0;
}

static void self_ipi_hanlder(struct dune_tf *tf)
{
    printf("ipi_handler_self: received IPI on core %d\n", sched_getcpu());
    apic_eoi();
    printf("ipi_handler_self: EOI sent\n");
}

int test_self_posted_ipi(int argc, char *argv[])
{
    printf("Hello from main thread\n");

    // register IPI handler
    dune_register_intr_handler(TEST_VECTOR, self_ipi_hanlder);

    // Send IPI to self
    apic_send_ipi(TEST_VECTOR, apic_get_id());

    printf("Sent IPI to self\n");

    return 0;
}

static void ipi_hanlder(struct dune_tf *tf)
{
    printf("ipi_handler: received IPI on core %d\n", sched_getcpu());
    apic_eoi();
    printf("ipi_handler: EOI sent\n");
    pthread_exit(NULL);
}

static void *ipi_thread(void *arg)
{
    // Enter VMPL mode
    volatile int ret = vmpl_enter(1, NULL);
    if (ret) {
        printf("posted_ipi: failed to enter dune in thread %d\n", sched_getcpu());
		return NULL;
    }

    // APIC init for VMPL mode
    apic_init_rt_entry();

    // register IPI handler
    dune_register_intr_handler(TEST_VECTOR, ipi_hanlder);

	asm volatile("mfence" ::: "memory");
	*(volatile bool *)arg = true;
	while (true);
	return NULL;
}

int test_posted_ipi(int argc, char *argv[])
{
	volatile int ret;
	cpu_set_t cpus;
	pthread_t pthreads[NUM_THREADS];
	volatile bool ready[NUM_THREADS];
	int i, apic_id;
	pthread_attr_t attr;

    // Pin main thread to core 3
    bind_cpu(MAIN_THREAD);

    // Show apic id of main thread
    apic_id = apic_get_id();
    printf("apic_id: %d\n", apic_id);

    // Start threads on other cores, i.e. cores 0, 1, 2
	for (i = 0; i < NUM_THREADS; i++) {
        // Initialize ready flag for thread i
		ready[i] = false;
        // Pin thread to core i (0, 1, 2)
		CPU_ZERO(&cpus);
		CPU_SET(i, &cpus);
        // Create thread i and set ready flag for thread i
		pthread_attr_init(&attr);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
#ifdef __GLIBC__
        pthread_attr_setaffinity_np(&attr, sizeof(cpu_set_t), &cpus);
#else
        pthread_setaffinity_np(pthreads[i], sizeof(cpu_set_t), &cpus);
#endif
		pthread_create(&pthreads[i], &attr, ipi_thread, (void *)&ready[i]);
	}

    // Wait for threads to start
    printf("Waiting for threads to start\n");
    for (i = 0; i < NUM_THREADS; i++) {
        while (!ready[i]);
    }
    asm volatile("mfence" ::: "memory");

    // Send IPIs to other cores
	printf("About to send posted IPIs to %d cores\n", NUM_THREADS);
	for (i = 0; i < NUM_THREADS; i++) {
        if (i != apic_id)
            apic_send_ipi(TEST_VECTOR, apic_get_id_for_cpu(i, NULL));
	}

    // Wait for threads to exit
	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join(pthreads[i], NULL);
	}

    return 0;
}

static int test_pgflt(int argc, char *argv[])
{
    char *addr_ro;
    addr_ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("addr_ro: %p\n", addr_ro);

    VMPL_ENTER;

    *addr_ro = 'a';

    printf("addr_ro: %c\n", *addr_ro);

    return 0;
}

#ifdef HAVE_SECCOMP
#include <seccomp.h>
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
        int ret;
        if (test->prolog != NULL) {
            ret = test->prolog(argc, argv); 
            if (ret) {
                printf("Enter dune mode failed!\n");
                exit(ret);
            }
        }
        if (test->exec_func) {
            ret = test->exec_func(argc, argv);
            exit(ret);
        }
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
    {"test_mxml", test_mxml, vmpl_enter},
    {"test_zlib", test_zlib, vmpl_enter},
    {"test_bitmap", test_bitmap, vmpl_enter},
    {"test_hbitmap", test_hbitmap, vmpl_enter},
    {"test_bmap", test_bmap, vmpl_enter},
    {"test_socket", test_socket, NULL},
    {"test_rdtsc", test_rdtsc, vmpl_enter},
    {"test_time", test_time, vmpl_enter},
    {"test_sys", test_sys, vmpl_enter},
    {"test_cpuid", test_cpuid, vmpl_enter},
    {"test_prctl", test_prctl, vmpl_enter},
    {"test_debug", test_debug, vmpl_enter},
    {"test_syscall", test_syscall, vmpl_enter},
    {"test_mmap", test_mmap, vmpl_enter},
    {"test_munmap", test_munmap, vmpl_enter},
    {"test_mprotect", test_mprotect, vmpl_enter},
    {"test_seimi", test_seimi, NULL},
    {"test_seimi_ro", test_seimi_ro, NULL},
    {"test_sbrk", test_sbrk, vmpl_enter},
    {"test_pipe", test_pipe, NULL},
    {"test_sem", test_sem, NULL},
    {"test_semaphore", test_semaphore, NULL},
    {"test_shm", tesh_shm, NULL},
    {"test_msg", test_msg, NULL},
    {"test_signal", test_signal, vmpl_enter},
    {"test_vsyscall", test_vsyscall, vmpl_enter},
    {"test_vdso", test_vdso, vmpl_enter},
    {"test_fork", test_fork, vmpl_enter},
    {"test_vfork", test_vfork, vmpl_enter},
    {"test_pthread", test_pthread, vmpl_enter},
    {"test_posted_ipi", test_posted_ipi, vmpl_enter},
    {"test_self_posted_ipi", test_self_posted_ipi, vmpl_enter},
    {"test_pgflt", test_pgflt, NULL},
#ifdef HAVE_SECCOMP
    {"test_seccomp", test_seccomp, vmpl_enter},
#endif
    {"vmpl_server", vmpl_server, vmpl_enter},
    {"vmpl_client", vmpl_client, vmpl_enter},
    {"bench_dune_ring", bench_dune_ring, NULL},
};

#define num_tests (sizeof(tests) / sizeof(Test))

struct test_args {
    char *test_name;
    int run_all;
    int list_tests;
    int show_help;
    int show_maps;
    int show_time;
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
    {"show-time", 's', 0, 0, "Show time", 1},
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
        case 's':
            args->show_time = 1;
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
    printf("Usage: %s [-a] [-t test_name] [-l] [-h] [-m] [-s] [-v log_level]\n", program_name);
}

static int parse_args(int argc, char *argv[], struct test_args *args) {
    int opt;
    while ((opt = getopt(argc, argv, "alt:hmsv:")) != -1) {
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
            case 's':
                args->show_time = 1;
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
        .show_time = 0,
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

    if (args.show_time) {
        set_show_time(true);
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