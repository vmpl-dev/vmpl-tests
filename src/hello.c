#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "cpu-x86.h"
#include "hypercall.h"
#include "vmpl.h"

static void recover(void)
{
	vmpl_puts("hello: recovered from divide by zero\n");
    hp_exit();
}

static void divide_by_zero_handler(struct dune_tf *tf)
{
	vmpl_puts("hello: caught divide by zero!\n");
	tf->rip = (uintptr_t)&recover;
}
int main(int argc, char *argv[])
{
	volatile int ret;

	printf("hello: not running dune yet\n");

	ret = vmpl_enter(argc, argv);
	if (ret) {
		vmpl_puts("failed to initialize dune\n");
		return ret;
	}

	vmpl_puts("hello: now printing from dune mode\n");

	dune_register_intr_handler(T_DIVIDE, divide_by_zero_handler);

	ret = 1 / ret; /* divide by zero */

	vmpl_puts("hello: we won't reach this call\n");

	return 0;
}
