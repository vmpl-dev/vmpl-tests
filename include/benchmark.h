#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <time.h>

#define CLOCK_MONOTONIC_RAW 4
#define NUM_ITERATIONS 1000

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"

// number of iterations for benchmarking the overhead of rdtsc and rdtscp instructions.
#define N	10000
// port number for the server to listen on.
#define PORT 8080
// number of bytes to send to the server.
#define SLEEP_TIME 3
#define THREAD_1_CORE 1
#define THREAD_2_CORE 2
#define THREAD_3_CORE 3
#define THREAD_4_CORE 4
// posted-ipi test constants
#define MAIN_THREAD 3
#define NUM_THREADS 3
#define TEST_VECTOR 0xF2

extern int vmpl_server(int argc, char const *argv[]);
extern int vmpl_client(int argc, char const *argv[]);
extern int bench_dune_ring(int argc, char const *argv[]);
extern int test_semaphore(int argc, char *argv[]);
extern int test_bitmap(int argc, char const *argv[]);

#ifdef __cplusplus
}
#endif