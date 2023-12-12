#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/wait.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <sys/prctl.h>

#define ARCH_GET_FS 0x1003
extern int arch_prctl(int code, unsigned long *addr);

struct regs_t {
	uint16_t cs;
	uint16_t ds;
	uint16_t es;
	uint16_t fs;
	uint16_t gs;
	uint16_t ss;
};

static void get_fs_base(char *name)
{
	unsigned long fs_base0, fs_base1, fs_base2;

	if (arch_prctl(ARCH_GET_FS, &fs_base0) == -1) {
		return;
	}

	__asm__ volatile("mov %%fs:0, %0\n" : "=r"(fs_base1));
	__asm__ volatile("rdfsbase %0\n" : "=r"(fs_base2));
    if (fs_base0!= fs_base1 || fs_base0!= fs_base2) {
		printf("%s fs_base0: %lx, fs_base1: %lx, fs_base2: %lx", name, fs_base0, fs_base1, fs_base2);
		printf("%s fs_base0!= fs_base1 || fs_base0!= fs_base2", name);
	} else {
        printf("%s fs_base=%lx", name, fs_base0);
    }
}

static void get_segment_registers(struct regs_t *regs)
{
	__asm__ volatile(
        "movw %%cs, %c[cs](%0)\n"
        "movw %%ds, %c[ds](%0)\n"
        "movw %%es, %c[es](%0)\n"
        "movw %%fs, %c[fs](%0)\n"
        "movw %%gs, %c[gs](%0)\n"
        "movw %%ss, %c[ss](%0)\n" ::"r"(regs),
        [cs] "i"(offsetof(struct regs_t, cs)),
        [ds] "i"(offsetof(struct regs_t, ds)),
        [es] "i"(offsetof(struct regs_t, es)),
        [fs] "i"(offsetof(struct regs_t, fs)),
        [gs] "i"(offsetof(struct regs_t, gs)),
        [ss] "i"(offsetof(struct regs_t, ss)));
}

#if 0
static void do_busy_loop() {
	// write a busy loop never be optimized out
	// sleep for 1s
	__asm__ volatile(
		"mov $1000000000, %%ecx\n"  // change eax to ecx
		"1:\n"
		"loop 1b\n"
		:
		:
		: "ecx"  // change eax to ecx
	);
}
#else 
void do_busy_loop(const char *name)
{
	struct regs_t regs;
	// get_fs_base(name);
	get_segment_registers(&regs);
	printf("%s cs=%x ds=%x es=%x fs=%x gs=%x ss=%x\n", name,
		   regs.cs, regs.ds, regs.es, regs.fs, regs.gs, regs.ss);
}
#endif

int main(int argc, char *argv[])
{
	int r, status;
	do_busy_loop("main");
	int p = fork();
	if (p < 0) {
		printf("fork error: %d\n", p);
		return 1;
	} else if (p == 0) {
		printf("in child\n");
		do_busy_loop("child");
		// r = usleep(1000);
		// printf("child done sleeping, usleep=%d, errno=%d\n", r, errno);
	} else {
		printf("in parent, child=%d, errno=%d\n", p, errno);
		do_busy_loop("parent");
		r = usleep(1000);
		printf("parent done sleeping, usleep=%d, errno=%d\n", r, errno);
		r = waitpid(p, &status, 0);
		printf("done waiting, waitpid=%d, errno=%d\n", r, errno);
	}
	return 0;
}
