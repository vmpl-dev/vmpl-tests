
#include <stdio.h>
#include <time.h>

int main(int argc, char *argv[])
{
	time_t t = -1;

	t = time(&t);
	if (t == -1) {
		printf("Error calling time(&t)!\n");
		return 1;
	}

	printf("Success! t=%ld\n", t);

	t = time(NULL);
	if (t == -1) {
		printf("Error calling time(NULL)!\n");
		return 1;
	}

	printf("Success! t=%ld\n", t);
	return 0;
}
