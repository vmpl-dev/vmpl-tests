#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <time.h>

#define CLOCK_MONOTONIC_RAW 4
#define NUM_ITERATIONS 1000000

#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_RESET   "\x1b[0m"

// number of iterations for benchmarking the overhead of rdtsc and rdtscp instructions.
#define N	10000
// port number for the server to listen on.
#define PORT 8080
// number of bytes to send to the server.
#define THREAD_1_CORE 1
#define THREAD_2_CORE 2

extern int vmpl_server(int argc, char const *argv[]);
extern int vmpl_client(int argc, char const *argv[]);
extern int bench_dune_ring(int argc, char const *argv[]);

#ifdef __cplusplus
}
#endif