#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>

#ifdef LIBDUNE
#include "libdune/dune.h"
#else
#include <vmpl/log.h>
#include <vmpl/sys.h>
#include <vmpl/syscall.h>
#include <vmpl/vmpl.h>
#include <vmpl/mm.h>
#endif

#define N		10000
#define MAP_ADDR	0x400000000000

static unsigned long tsc;

#ifdef LIBDUNE
static void pgflt_handler(uintptr_t addr, uint64_t fec, struct dune_tf *tf)
{
	ptent_t *pte;

	dune_vm_lookup(pgroot, (void *) addr, 0, &pte);
	*pte |= PTE_P | PTE_W | PTE_U | PTE_A | PTE_D;
}
#else
static void pgflt_handler(uintptr_t addr, uint64_t fec, struct dune_tf *tf)
{
	// ptent_t *pte;

	// dune_vm_lookup(pgroot, (void *) addr, 0, &pte);
	// *pte |= PTE_P | PTE_W | PTE_U | PTE_A | PTE_D;

	log_err("page fault at %p", (void *) addr);

	exit(0);
}
#endif

#ifndef LIBDUNE
static void dune_passthrough_syscall(struct dune_tf *tf)
{
	__syscall6(tf->rax, tf->rdi, tf->rsi, tf->rdx, tf->r10, tf->r8, tf->r9);
}
#endif

static void syscall_handler1(struct dune_tf *tf)
{
	dune_ret_from_user(0);

	log_info("syscall_handler1 running.");

	dune_passthrough_syscall(tf);
}

static void userlevel_pgflt(void)
{
	log_info("userlevel_pgflt running.");
#ifdef LIBDUNE
	char *p = (char *) MAP_ADDR;
	*p = 1;
#else
	log_warn("memory mapping not supported in VMPL (yet)");
#endif

	syscall(SYS_gettid);
}

static int test_pgflt(void)
{
	int ret;
	unsigned long sp;
	struct dune_tf *tf = malloc(sizeof(struct dune_tf));
	if (!tf)
		return -ENOMEM;

	log_info("testing page fault from G3... ");

#ifdef LIBDUNE
	ret = dune_vm_map_pages(pgroot, (void *) MAP_ADDR, 1, PERM_R);
	if (ret) {
		log_err("failed to setup memory mapping");
		return ret;
	}
#else
	ret = mmap((void *)MAP_ADDR, 1, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (ret == MAP_FAILED) {
		log_err("failed to setup memory mapping");
		return ret;
	}
	log_warn("memory mapping not supported in VMPL (yet)");
#endif

	dune_register_pgflt_handler(pgflt_handler);
	dune_register_syscall_handler(&syscall_handler1);

	asm ("movq %%rsp, %0" : "=r" (sp));

	tf->rip = (unsigned long) &userlevel_pgflt;
	tf->rsp = sp - 10000;
	tf->rflags = 0x02;

	ret = dune_jump_to_user(tf);

	if (!ret)
		log_success("[passed]\n");

	return ret;
}

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

static int test_syscall(void)
{
	int ret;
	unsigned long sp;
	struct dune_tf *tf = malloc(sizeof(struct dune_tf));
	if (!tf)
		return -ENOMEM;

	log_info("measuring round-trip G3 syscall performance... ");

	dune_register_syscall_handler(&syscall_handler2);

	asm ("movq %%rsp, %0" : "=r" (sp));

	tf->rip = (unsigned long) &userlevel_syscall;
	tf->rsp = sp - 10000;
	tf->rflags = 0x0;

	tsc = rdtsc();
	ret = dune_jump_to_user(tf);

	return ret;
}

int bench_dune_ring(int argc, char *argv[])
{
	int ret;

#ifdef LIBDUNE
	ret = dune_init_and_enter();
	if (ret) {
		printf("failed to initialize DUNE\n");
		return ret;
	}
#endif

	// test_pgflt();
	test_syscall();

	return 0;
}
