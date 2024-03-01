#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <check.h>

#include "benchmark.h"

START_TEST (test_signal)
{
    pid_t pid = fork();
    if (pid == 0) { // This is the child process
        signal(SIGUSR1, SIG_DFL); // Set the signal handler to the default
        pause(); // Wait for any signal
        exit(0);
    } else { // This is the parent process
        kill(pid, SIGUSR1); // Send the signal to the child
        int status;
        waitpid(pid, &status, 0); // Wait for the child to exit
        ck_assert_int_eq(WIFSIGNALED(status), 1); // Check if the child was signaled
        ck_assert_int_eq(WTERMSIG(status), SIGUSR1); // Check if the signal was SIGUSR1
    }
}
END_TEST

Suite* signal_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Signal");

    /* Core test case */
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_signal);

    suite_add_tcase(s, tc_core);

    return s;
}