#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <sys/syscall.h>
#include <vmpl/sys.h>
#include <vmpl/vmpl.h>
#include <vmpl/log.h>

#include <hotcalls/hotcalls.h>
#define NUM_ITERATIONS 10000

int hotcalls_write(int fd, const void *buf, size_t count)
{
    hotcall_args_t args = {
        .sysnr = SYS_write,
        .rdi = fd,
        .rsi = (uint64_t)buf,
        .rdx = count,
    };
    return hotcalls_call(&args);
}

int benchmark(hotcall_args_t *args, long (*func)(hotcall_args_t *))
{
    uint64_t start_time, end_time, total_time;
    start_time = rdtscp();
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        func(args);
    }
    end_time = rdtscp();
    total_time = end_time - start_time;
    log_success("Average Elapsed Time: %lu ns", total_time / NUM_ITERATIONS);
    return 0;
}

int main(int argc, char *argv[]) {
    hotcall_args_t args = {
        .sysnr = SYS_getpid,
    };

    log_info("enter main...");
    hotcalls_setup(1);
    log_info("setup finish ");

    log_info("Test syscalls before entering vmpl");
    benchmark(&args, syscalls_call);
    log_info("Test hotcalls before entering vmpl");
    benchmark(&args, hotcalls_call);

    log_info("enter vmpl...");
    VMPL_ENTER;
    log_info("enter vmpl finish ");
    hotcalls_write(1, "hello world\n", 12);

    log_info("Test syscalls after entering vmpl");
    benchmark(&args, syscalls_call);
    log_info("Test hotcalls after entering vmpl");
    benchmark(&args, hotcalls_call);

    log_info("call finish ");
    hotcalls_teardown();
    return 0;
}