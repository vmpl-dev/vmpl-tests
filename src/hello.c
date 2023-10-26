#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// #include "cpu-x86.h"
#ifdef USE_GLIBC
#include "hypercall.h"
#include "utils.h"
#include "args.h"
#else
#include <sys/mman.h>
#include <sys/resource.h>
#endif
#include "sys.h"
#include "vmpl.h"

static void recover(void)
{
	printf("hello: recovered from divide by zero\n");
    exit(EXIT_FAILURE);
}

static void divide_by_zero_handler(struct dune_tf *tf)
{
	printf("hello: caught divide by zero!\n");
	tf->rip = (uintptr_t)&recover;
}

int main(int argc, char *argv[])
{
	volatile int ret = 0;

	printf("hello: not running dune yet\n");

	VMPL_ENTER;

	printf("hello: now printing from dune mode\n");

	dune_register_intr_handler(T_DE, divide_by_zero_handler);

	// show_segment_registers();

	ret = 1 / ret; /* divide by zero */

	printf("hello: we won't reach this call\n");

	return 0;
}
