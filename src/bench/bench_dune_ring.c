#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#include <vmpl/log.h>
#include <vmpl/dune.h>

#include "benchmark.h"

#define N		10000
#define MAP_ADDR	0x400000000000

static unsigned long tsc;

static void pgflt_handler(uintptr_t addr, uint64_t fec, struct dune_tf *tf)
{
	ptent_t *pte;

	dune_vm_lookup(pgroot, (void *) addr, 0, &pte);
	*pte |= PTE_P | PTE_W | PTE_U | PTE_A | PTE_D;
}

static void syscall_handler1(struct dune_tf *tf)
{
	dune_ret_from_user(0);

	log_info("syscall_handler1 running.");

	dune_passthrough_syscall(tf);
}

static void userlevel_pgflt(void)
{
	log_info("userlevel_pgflt running.");
	char *p = (char *) MAP_ADDR;
	*p = 1;

	syscall(SYS_gettid);
}

START_TEST(test_pgflt)
	int ret;
	void *addr;
	unsigned long sp;
	struct dune_tf *tf = malloc(sizeof(struct dune_tf));
	ck_assert_ptr_ne(tf, NULL);

	log_info("testing page fault from G3... ");

	addr = mmap((void *)MAP_ADDR, 1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	ck_assert_ptr_ne(addr, MAP_FAILED);

	log_warn("memory mapping not supported in VMPL (yet)");

	dune_register_pgflt_handler(pgflt_handler);
	dune_register_syscall_handler(&syscall_handler1);

	asm ("movq %%rsp, %0" : "=r" (sp));

	tf->rip = (unsigned long) &userlevel_pgflt;
	tf->rsp = sp - 10000;
	tf->rflags = 0x02;

	ret = dune_jump_to_user(tf);
	ck_assert_int_eq(ret, 0);
END_TEST

static void userlevel_syscall(void)
{
	log_info("userlevel_syscall running.");
	int i;
	for (i = 0; i < N; i++) {
		syscall(SYS_gettid);
	}
}

static void syscall_handler2(struct dune_tf *tf)
{
	static int syscall_count = 0;

	syscall_count++;
	if (syscall_count == N) {
		log_info("[took %ld cycles]\n",
		       (rdtsc() - tsc) / N);
		dune_ret_from_user(0);
	}
	dune_passthrough_syscall(tf);
}

START_TEST(test_syscall)
	int ret;
	unsigned long sp;
	struct dune_tf *tf = malloc(sizeof(struct dune_tf));
	ck_assert_ptr_ne(tf, NULL);

	log_info("measuring round-trip G3 syscall performance... ");

	dune_register_syscall_handler(&syscall_handler2);

	asm ("movq %%rsp, %0" : "=r" (sp));

	tf->rip = (unsigned long) &userlevel_syscall;
	tf->rsp = sp - 10000;
	tf->rflags = 0x0;

	tsc = rdtsc();
	ret = dune_jump_to_user(tf);
	ck_assert_int_eq(ret, 0);
END_TEST

Suite *bench_dune_ring(void)
{
	Suite *s;
	TCase *tc_core;

	s = suite_create("Dune ring");

	/* Core test case */
	tc_core = tcase_create("Core");

	tcase_add_test(tc_core, test_pgflt);
	tcase_add_test(tc_core, test_syscall);
	suite_add_tcase(s, tc_core);

	return s;
}