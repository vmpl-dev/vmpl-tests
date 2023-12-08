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
#include <sys/time.h> // gettimeofday
#include <time.h> // time
#include <pthread.h> // pthread_create, pthread_join
#include <sched.h>
#include <sys/ipc.h> // shmget, shmctl, ftok, IPC_CREAT 
#include <sys/sem.h> // semget, semctl, semop
#include <sys/shm.h> // shmget, shmctl, shmat, shmdt
#include <sys/msg.h>
#include <sys/wait.h> // waitpid, WIFEXITED, WEXITSTATUS, WTERMSIG
#include <semaphore.h>
#include <vmpl/sys.h> // read_cr0, read_cr2, read_cr3, read_cr4, read_rflags, rdmsr
#include <vmpl/apic.h>
#include <vmpl/mm.h>
#include <vmpl/vmpl.h>  // vmpl_enter, vmpl_server, vmpl_client
#include <vmpl/seimi.h> // sa_alloc, sa_free
#include <vmpl/log.h> // log_init, log_set_level

#include "config.h"
#include "benchmark.h"

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
        exit(EXIT_FAILURE);
    }

    // rest of your code
    return 0;
}

void handle_sigint(int sig)
{
    printf("Caught signal %d\n", sig);
    exit(EXIT_SUCCESS);
}

START_TEST(test_process)
{
    VMPL_ENTER;
    printf("vmpl-process: hello world!\n");

    int fd;
    ssize_t num_read;
    fd = open("/proc/self/maps", O_RDONLY, 0);
    ck_assert_ptr_ne(fd, -1);

    while ((num_read = read(fd, line, 1024)) > 0) {
        ssize_t num_written = write(STDOUT_FILENO, line, num_read);
        ck_assert_int_eq(num_written, num_read);
    }

    ck_assert_int_ne(num_read, -1);
    ck_assert_int_ne(close(fd), -1);
}
END_TEST

START_TEST(test_socket)
{
    VMPL_ENTER;
    pid_t server_pid = fork();
    if (server_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (server_pid == 0) {
        // Child process
        bind_cpu(THREAD_1_CORE);
        VMPL_ENTER;
        vmpl_server(1, NULL);
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
            vmpl_client(1, NULL);
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
}
END_TEST

START_TEST(test_sys)
{
    VMPL_ENTER;
    printf("cr0: 0x%lx\n", read_cr0());
    printf("cr2: 0x%lx\n", read_cr2());
    printf("cr3: 0x%lx\n", read_cr3());
    printf("cr4: 0x%lx\n", read_cr4());
    printf("efer: 0x%lx\n", rdmsr(MSR_EFER));
    printf("rflags: 0x%lx\n", read_rflags());
}
END_TEST

static void vc_handler(struct dune_tf *tf)
{
    printf("vc_handler: received VMM communication\n");
    exit(EXIT_SUCCESS);
}

START_TEST(test_cpuid)
{
    VMPL_ENTER;
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
}
END_TEST

START_TEST(test_vsyscall)
{
    VMPL_ENTER;
    struct timeval tv;
    struct timezone tz;

    /* 测试 gettimeofday 函数 */
    ck_assert_int_eq(gettimeofday(&tv, &tz), 0);

    /* 测试 time 函数 */
    ck_assert_int_ne(time(NULL), -1);
}
END_TEST

START_TEST(test_vdso)
{
    VMPL_ENTER;
    int a = getpid();
    int b = getpid();

    ck_assert_int_eq(a, b);
}
END_TEST

START_TEST(test_signal)
{
    VMPL_ENTER;
    signal(SIGINT, handle_sigint);
}
END_TEST

START_TEST(test_debug)
{
    VMPL_ENTER;
    // 读取DR0-DR7的值并打印
    printf("dr0: 0x%lx\n", read_dr(0));
    printf("dr1: 0x%lx\n", read_dr(1));
    printf("dr2: 0x%lx\n", read_dr(2));
    printf("dr3: 0x%lx\n", read_dr(3));
    printf("dr6: 0x%lx\n", read_dr(6));
    printf("dr7: 0x%lx\n", read_dr(7));
}
END_TEST

START_TEST(test_prctl)
{
    VMPL_ENTER;
    int ret_fs, ret_gs;
    unsigned long fs_reg_value;
    unsigned long gs_reg_value;

    ret_fs = arch_prctl(ARCH_GET_FS, &fs_reg_value);
    ck_assert_int_eq(ret_fs, 0);
    ck_assert_int_ne(fs_reg_value, 0);
    ret_gs = arch_prctl(ARCH_GET_GS, &gs_reg_value);

    ck_assert_int_eq(ret_gs, 0);
    ck_assert_int_ne(gs_reg_value, 0);
}
END_TEST

START_TEST(test_syscall)
{
    VMPL_ENTER;
    int fd = open("/dev/zero", O_RDONLY);
    ck_assert_int_ne(fd, -1);
    close(fd);
}
END_TEST

START_TEST(test_rdtsc)
{
    VMPL_ENTER;
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
}
END_TEST

START_TEST(test_time_vdso)
{
    VMPL_ENTER;
    uint64_t start_time, end_time;
    uint64_t total_time = 0;

    start_time = get_time();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        time(NULL);
    }
    end_time = get_time();
    total_time = end_time - start_time;

    printf("Elapsed time: %lu ns\n", total_time);
}
END_TEST

START_TEST(test_time_syscall)
{
    VMPL_ENTER;
    uint64_t start_time, end_time;
    uint64_t total_time = 0;

    start_time = get_time();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        syscall(SYS_time, NULL);
    }
    end_time = get_time();
    total_time = end_time - start_time;

    printf("Elapsed time: %lu ns\n", total_time);

}
END_TEST

START_TEST(test_time)
{
    VMPL_ENTER;
    pid_t pid;
    uint64_t start_time;
    uint64_t end_time;
    uint64_t total_time = 0;

    start_time = get_time();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        pid = getpid();
    }
    end_time = get_time();
    total_time = end_time - start_time;


    printf("Elapsed time: %lu ns\n", total_time);

    start_time = rdtsc();
    for (int i = 0; i < NUM_ITERATIONS; i++)
    {
        pid = getpid();
    }
    end_time = rdtsc();
    total_time = end_time - start_time;

    printf("Average time: %lu cycles\n", total_time / NUM_ITERATIONS);
}
END_TEST

START_TEST(test_mmap)
{
    VMPL_ENTER;
    int fd = open("file.txt", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
    } else {
        printf("mmap: %p\n", addr);
        close(fd);
    }
}
END_TEST

START_TEST(test_mprotect)
{
    VMPL_ENTER;
    int fd = open("file.txt", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_ptr_ne(addr, MAP_FAILED);
    printf("addr: %p\n", addr);
    int ret = mprotect(addr, 4096, PROT_READ | PROT_WRITE);
    ck_assert_int_eq(ret, 0);
    close(fd);
}
END_TEST

START_TEST(test_munmap)
{
    VMPL_ENTER;
    int fd = open("file.txt", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_ptr_ne(addr, MAP_FAILED);
    printf("addr: %p\n", addr);
    int ret = munmap(addr, 4096);
    ck_assert_int_eq(ret, 0);
    close(fd);
}
END_TEST

START_TEST(test_seimi)
{
    VMPL_ENTER;
    char *seimi_user;

    // Allocate 4096 bytes of memory
    seimi_user = sa_alloc(4096, false, NULL);
    sprintf(seimi_user, "Hello, world!");

    // Print the address of seimi_user
    printf("seimi_user: %s\n", seimi_user);

    // Now, we enter VMPL mode
    printf("seimi_user[vmpl]: %p\n", seimi_user);

    // Write to seimi_user (protected)
    __asm__ volatile("stac\n");
    sprintf(seimi_user, "Hello, SEIMI!");
    printf("seimi_user: %s\n", seimi_user);
    __asm__ volatile("clac\n");

    sa_free(seimi_user, 4096);
}
END_TEST

START_TEST(test_seimi_ro)
{
    VMPL_ENTER;
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

}
END_TEST

START_TEST(test_sbrk)
{
    VMPL_ENTER;
    void *cur_brk, *tmp_brk = NULL;

    printf("The original program break: %p\n", sbrk(0));

    tmp_brk = sbrk(4096);
    ck_assert_ptr_ne(tmp_brk, (void *)-1);

    cur_brk = sbrk(0);
    printf("The program break after incrementing: %p\n", cur_brk);

    tmp_brk = sbrk(-4096);
    ck_assert_ptr_ne(tmp_brk, (void *)-1);

    cur_brk = sbrk(0);
    printf("The program break after decrementing: %p\n", cur_brk);

}
END_TEST

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

START_TEST(test_sem)
{
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
}
END_TEST

START_TEST(test_pipe)
{
    VMPL_ENTER;
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
        close(pipefd[1]);          /* Close unused write end */

        while (read(pipefd[0], &buf, 1) > 0)
            write(STDOUT_FILENO, &buf, 1);

        write(STDOUT_FILENO, "\n", 1);
        close(pipefd[0]);
        _exit(EXIT_SUCCESS);

    } else {            /* Parent writes argv[1] to pipe */
        close(pipefd[0]);          /* Close unused read end */
        write(pipefd[1], "test", 4);
        close(pipefd[1]);          /* Reader will see EOF */
        wait(NULL);                /* Wait for child */
        exit(EXIT_SUCCESS);
    }
}
END_TEST

#define SHM_SIZE 1024

START_TEST(test_shm)
{
    int shmid;
    key_t key;
    pid_t pid1, pid2;
    char *shm;

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
        sprintf(shm, "Hello, world!");
        printf("shm: %s\n", shm);
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
        printf("shm: %s\n", shm);
        shmdt(shm);
        exit(0);
    }

    // 等待子进程结束
    waitpid(pid1, NULL, 0);
    waitpid(pid2, NULL, 0);

    // 删除共享内存
    shmctl(shmid, IPC_RMID, NULL);

}
END_TEST

#define MSG_SIZE 1024

struct msgbuf_t {
    long mtype;             /* message type, must be > 0 */
    char mtext[MSG_SIZE];   /* message data */
};

START_TEST(test_msg)
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
}
END_TEST

START_TEST(test_fork)
{
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        printf("Child process\n");
        VMPL_ENTER;
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

}
END_TEST

START_TEST(test_vfork)
{
    /* vfork syscall cannot be made from C code */
    pid_t pid = vfork();
    if (pid == -1) {
        perror("vfork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        // Child process
        printf("Child process\n");
        VMPL_ENTER;
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

}
END_TEST

void *thread_func(void *arg)
{
    printf("Hello from thread\n");
    VMPL_ENTER;
    return NULL;
}

START_TEST(test_pthread)
{
    pthread_t thread;
    printf("Hello from main thread\n");
    int rc = pthread_create(&thread, NULL, thread_func, NULL);
    ck_assert_int_eq(rc, 0);

    pthread_join(thread, NULL);
    printf("Joined thread\n");
}
END_TEST

static void self_ipi_hanlder(struct dune_tf *tf)
{
    printf("ipi_handler_self: received IPI on core %d\n", sched_getcpu());
    apic_eoi();
    printf("ipi_handler_self: EOI sent\n");
}

START_TEST(test_self_posted_ipi)
{
    VMPL_ENTER;
    printf("Hello from main thread\n");

    // register IPI handler
    dune_register_intr_handler(TEST_VECTOR, self_ipi_hanlder);

    // Send IPI to self
    apic_send_ipi(TEST_VECTOR, apic_get_id());

    printf("Sent IPI to self\n");

}
END_TEST

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

START_TEST(test_posted_ipi)
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
		int rc = pthread_create(&pthreads[i], &attr, ipi_thread, (void *)&ready[i]);
        ck_assert_int_eq(rc, 0);
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

}
END_TEST

static void pgflt_handler(struct dune_tf *tf)
{
    int rc, level;
	uint64_t cr2 = read_cr2();
	pte_t *ptep;
	log_warn("dune: page fault at 0x%016lx, error-code = %x", cr2, tf->err);
	rc = lookup_address(cr2, &level, &ptep);
	if (rc != 0) {
		log_err("dune: page fault at unmapped addr 0x%016lx", cr2);
	} else {
		log_warn("dune: page fault at mapped addr 0x%016lx", cr2);
        *ptep |= PTE_PRESENT | PTE_WRITE;
    }
}

START_TEST(test_pgflt)
{
    VMPL_ENTER;
    char *addr_ro;
    addr_ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ck_assert_ptr_ne(addr_ro, MAP_FAILED);

    dune_register_pgflt_handler(pgflt_handler);
    *addr_ro = 1;
}
END_TEST

#ifdef USE_SECCOMP
#include <seccomp.h> /* libseccomp */
START_TEST(test_seccomp)
{
    VMPL_ENTER;
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
}
END_TEST
#endif


Suite *sys_suite(void)
{
    Suite *s;

    s = suite_create("System Calls");

    /* Core test case */
    TCase *tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_process);
    tcase_add_test(tc_core, test_sys);
    tcase_add_test(tc_core, test_prctl);
    tcase_add_test(tc_core, test_rdtsc);
    // tcase_add_test(tc_core, test_cpuid); // #VC exception
    // tcase_add_test(tc_core, test_debug); // Segmentation fault
    tcase_add_test(tc_core, test_syscall);
    tcase_add_test(tc_core, test_vsyscall);

    suite_add_tcase(s, tc_core);

    return s;
}

Suite *proc_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Process Management");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_fork);
    tcase_add_test(tc_core, test_vfork);
    tcase_add_test(tc_core, test_pthread);
    // tcase_add_test(tc_core, test_posted_ipi);
    // tcase_add_test(tc_core, test_self_posted_ipi);

    suite_add_tcase(s, tc_core);

    return s;
}

Suite *vm_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Virtual Memory");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_mmap);
    tcase_add_test(tc_core, test_mprotect);
    tcase_add_test(tc_core, test_munmap);
    tcase_add_test(tc_core, test_sbrk);

    suite_add_tcase(s, tc_core);

    return s;    
}

Suite *ipc_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Inter-Process Communication");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_socket);
    tcase_add_test(tc_core, test_pipe);
    tcase_add_test(tc_core, test_sem);
    tcase_add_test(tc_core, test_msg);
    tcase_add_test(tc_core, test_shm);
    tcase_add_test(tc_core, test_signal);

    suite_add_tcase(s, tc_core);

    return s;
}

Suite *vdso_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("vDSO");

    /* Core test case */
    tc_core = tcase_create("Core");
    tcase_add_test(tc_core, test_vdso);
    tcase_add_test(tc_core, test_time_vdso);
    tcase_add_test(tc_core, test_time_syscall);
    tcase_add_test(tc_core, test_time);

    suite_add_tcase(s, tc_core);

    return s;
}

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");

    /* Core test case */
    tc_core = tcase_create("Core");

#ifdef USE_SECCOMP
    tcase_add_test(tc_core, test_seccomp);
#endif

    suite_add_tcase(s, tc_core);

    return s;
}

Suite *seimi_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("seimi");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_seimi);
    // tcase_add_test(tc_core, test_seimi_ro);

    suite_add_tcase(s, tc_core);

    return s;
}

Suite *misc_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Miscellaneous");

    /* Core test case */
    tc_core = tcase_create("Core");

    suite_add_tcase(s, tc_core);

    return s;
}

int main(int argc, char *atgv[])
{
    int number_failed;
    Suite *sys, *proc, *vm, *ipc, *vdso, *security, *seimi, *misc, *xml, *zlib;
    SRunner *sr;

    sys = sys_suite();
    proc = proc_suite();
    vm = vm_suite();
    ipc = ipc_suite();
    vdso = vdso_suite();
    security = security_suite();
    seimi = seimi_suite();
    misc = misc_suite();
    xml = xml_suite();
    zlib = zlib_suite();

    sr = srunner_create(NULL);
    srunner_add_suite(sr, sys);
    srunner_add_suite(sr, proc);
    srunner_add_suite(sr, vm);
    srunner_add_suite(sr, ipc);
    srunner_add_suite(sr, vdso);
    srunner_add_suite(sr, xml);
    srunner_add_suite(sr, zlib);
    srunner_add_suite(sr, security);
    srunner_add_suite(sr, seimi);
    srunner_add_suite(sr, misc);

    srunner_set_log(sr, "test.log");
    srunner_set_xml(sr, "test.xml");
    srunner_set_fork_status(sr, CK_FORK);
    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}