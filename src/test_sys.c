#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <sys/time.h>
#include <vmpl/vmpl.h>
#include <vmpl/sys.h>

#include "benchmark.h"

static char line[1024];

START_TEST(test_process)
{
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

START_TEST(test_sys)
{
    printf("cr0: 0x%lx\n", read_cr0());
    printf("cr2: 0x%lx\n", read_cr2());
    printf("cr3: 0x%lx\n", read_cr3());
    printf("cr4: 0x%lx\n", read_cr4());
    printf("efer: 0x%lx\n", rdmsr(MSR_EFER));
    printf("rflags: 0x%lx\n", read_rflags());
}
END_TEST

START_TEST(test_prctl)
{
    int ret_fs, ret_gs;
    unsigned long fs_reg_value;
    unsigned long gs_reg_value;

    ret_fs = arch_prctl(ARCH_GET_FS, &fs_reg_value);
    ck_assert_int_eq(ret_fs, 0);
    ck_assert_int_ne(fs_reg_value, 0);
    ret_gs = arch_prctl(ARCH_GET_GS, &gs_reg_value);

    ck_assert_int_eq(ret_gs, 0);
    ck_assert_int_eq(gs_reg_value, 0);
}
END_TEST

START_TEST(test_rdtsc)
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
}
END_TEST

static void vc_handler(struct dune_tf *tf)
{
    printf("vc_handler: received VMM communication\n");
    exit(EXIT_SUCCESS);
}

START_TEST(test_cpuid)
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
}
END_TEST

static void pf_handler(struct dune_tf *tf)
{
    exit(EXIT_SUCCESS);
}

START_TEST(test_debug)
{
    dune_register_intr_handler(T_PF, pf_handler);

    // 读取DR0-DR7的值并打印
    printf("dr0: 0x%lx\n", read_dr(0));
    printf("dr1: 0x%lx\n", read_dr(1));
    printf("dr2: 0x%lx\n", read_dr(2));
    printf("dr3: 0x%lx\n", read_dr(3));
    printf("dr6: 0x%lx\n", read_dr(6));
    printf("dr7: 0x%lx\n", read_dr(7));
}
END_TEST

START_TEST(test_syscall)
{
    // 测试 open 系统调用
    int fd = open("/dev/zero", O_RDONLY, 0);
    ck_assert_int_ne(fd, -1);

    // 测试 close 系统调用
    ck_assert_int_eq(close(fd), 0);
}
END_TEST

START_TEST(test_vsyscall)
{
    struct timeval tv;
    struct timezone tz;

    /* 测试 gettimeofday 函数 */
    ck_assert_int_eq(gettimeofday(&tv, &tz), 0);

    /* 测试 time 函数 */
    ck_assert_int_ne(time(NULL), -1);
}
END_TEST

Suite *sys_suite(void)
{
    Suite *s;

    s = suite_create("System Calls");

    /* Core test case */
    TCase *tc_core = tcase_create("System");

    tcase_add_test(tc_core, test_process);
    tcase_add_test_raise_signal(tc_core, test_sys, SIGSEGV);
    tcase_add_test(tc_core, test_prctl);
    tcase_add_test(tc_core, test_rdtsc);
    tcase_add_test(tc_core, test_cpuid); // #VC exception
    tcase_add_test_raise_signal(tc_core, test_debug, SIGSEGV);
    tcase_add_test(tc_core, test_syscall);
    tcase_add_test(tc_core, test_vsyscall);

    suite_add_tcase(s, tc_core);

    return s;
}