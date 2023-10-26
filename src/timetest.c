
#include <stdio.h>
#include <time.h>

#ifdef DUNE_TEST
#include "libdune/dune.h"
#else
#include <vmpl/vmpl.h>
#endif

int main(int argc, char *argv[])
{
	time_t t = -1;

	int ret = dune_init_and_enter();
	if (ret) {
		printf("Failed to enter dune mode\n");
		return ret;
	}

	t = time(&t);
	if (t == -1) {
		printf("Error calling time(&t)!\n");
		return 1;
	}

	t = -1;
	t = time(NULL);
	if (t == -1) {
		printf("Error calling time(NULL)!\n");
		return 1;
	}

	printf("Success! t=%ld\n", t);
	return 0;
}
