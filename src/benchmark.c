// FILEPATH: /home/benshan/my-toy/test/src/benchmark.c
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <unistd.h>

#include "benchmark.h"

int bind_cpu(int cpu)
{
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(cpu, &mask);
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_setaffinity");
        exit(EXIT_FAILURE);
    }

    // rest of your code
    return 0;
}

// Define a argument struct for this benchmark
struct bench_args_t {
    char *log_file;
};

int parse_args(struct bench_args_t *args, int argc, char *argv[])
{
    int opt;
    while ((opt = getopt(argc, argv, "l:")) != -1) {
        switch (opt) {
        case 'l':
            args->log_file = optarg;
            break;
        default:
            printf("Usage: %s [-l log_file]\n", argv[0]);
            return -1;
        }
    }
    return 0;
}

int main(int argc, char *atgv[])
{
    int number_failed;
    Suite *sys, *proc, *vm, *ipc, *vdso, *security, *seimi, *misc, *xml, *zlib;
    SRunner *sr;

    struct bench_args_t args;
    if (parse_args(&args, argc, atgv) < 0) {
        return EXIT_FAILURE;
    }

    sys = sys_suite();
    proc = proc_suite();
    vm = vm_suite();
    ipc = ipc_suite();
    vdso = vdso_suite();
    security = security_suite();
    misc = misc_suite();
    xml = xml_suite();
    zlib = zlib_suite();

    sr = srunner_create(NULL);
    // srunner_add_suite(sr, sys);
    // srunner_add_suite(sr, proc);
    // srunner_add_suite(sr, vm);
    // srunner_add_suite(sr, ipc);
    srunner_add_suite(sr, vdso);
    srunner_add_suite(sr, xml);
    srunner_add_suite(sr, zlib);
    srunner_add_suite(sr, security);
    srunner_add_suite(sr, misc);

    if (strcmp(args.log_file, "stdout") == 0) {
        srunner_set_log(sr, NULL);
    } else if (strstr(args.log_file, ".log") != NULL) {
        srunner_set_log(sr, args.log_file);
    } else if (strstr(args.log_file, ".xml") != NULL) {
        srunner_set_xml(sr, args.log_file);
    } else {
        printf("Invalid log file: %s\n", args.log_file);
        return EXIT_FAILURE;
    }

    srunner_set_fork_status(sr, CK_FORK);
    srunner_run_all(sr, CK_VERBOSE);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}