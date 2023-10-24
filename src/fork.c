#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef DUNE_TEST
#include "libdune/dune.h"
#include "libdune/cpu-x86.h"
#else
#include "vmpl.h"
#include "cpu-x86.h"
#endif

int main(int argc, char *argv[])
{
	if (dune_init_and_enter() != 0) {
		printf("failed to init dune\n");
		return 1;
	}

	int p = fork();
	if (p < 0) {
		printf("fork error: %d\n", p);
		return 1;
	} else if (p == 0) {
		printf("in child\n");
		usleep(1000 * 1000);
		printf("done sleeping\n");
	} else {
		usleep(1000);
		printf("child=%d\n", p);
		if (waitpid(p, NULL, 0) == -1) {
			printf("waitpid error\n");
			return 1;
		}
		printf("done waiting\n");
	}
}
