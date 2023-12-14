#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/wait.h>
#include <vmpl/vmpl.h>
#include <vmpl/apic.h>

#include "benchmark.h"

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

Suite *proc_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Process Management");

    /* Core test case */
    tc_core = tcase_create("Process");

    tcase_add_test(tc_core, test_fork);
    tcase_add_test(tc_core, test_vfork);
    tcase_add_test(tc_core, test_pthread);
    tcase_add_test(tc_core, test_posted_ipi);
    tcase_add_test(tc_core, test_self_posted_ipi);

    suite_add_tcase(s, tc_core);

    return s;
}