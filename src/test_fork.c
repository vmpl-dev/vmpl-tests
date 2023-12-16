#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <vmpl/vmpl.h>

int main() {

    printf("Main process: PID = %d\n", getpid());
    pid_t pid = fork();
    int wstatus;

    if (pid < 0) {
        // Fork failed
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        // This is the child process
        printf("This is the child process\n");
        printf("Child process: PID = %d\n", getpid());
        printf("Child process: VMPL_ENTER\n");
    } else {
        // This is the parent process
        printf("This is the parent process\n");
        printf("Parent process: PID = %d, child's PID = %d\n", getpid(), pid);
        // Wait for the child process to finish
        if (wait(&wstatus) == -1) {
            perror("wait failed");
            return 1;
        }

        if (WIFEXITED(wstatus)) {
            printf("exited, status=%d\n", WEXITSTATUS(wstatus));
        } else if (WIFSIGNALED(wstatus)) {
            printf("killed by signal %d\n", WTERMSIG(wstatus));
        } else if (WIFSTOPPED(wstatus)) {
            printf("stopped by signal %d\n", WSTOPSIG(wstatus));
        } else if (WIFCONTINUED(wstatus)) {
            printf("continued\n");
        }
    }

    return 0;
}