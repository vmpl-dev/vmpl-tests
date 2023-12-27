#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <pthread.h>
#include <vmpl/vmpl.h>

int main() {
    // read fs,gs and print fs,gs; rdfsbase, rdgsbase and print
    unsigned long fs, gs, fsbase, gsbase;
    __asm__ __volatile__("mov %%fs, %0" : "=r"(fs));
    __asm__ __volatile__("mov %%gs, %0" : "=r"(gs));
    printf("fs = %lx, gs = %lx\n", fs, gs);
    __asm__ __volatile__("rdfsbase %0" : "=r"(fsbase));
    __asm__ __volatile__("rdgsbase %0" : "=r"(gsbase));
    printf("fsbase = %lx, gsbase = %lx\n", fsbase, gsbase);
    printf("Main process: PID = %d\n", getpid());
    pthread_t self = pthread_self();
    printf("Main process: pthread_self() = %p\n", self);
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
        self = pthread_self();
        printf("Main process: pthread_self() = %p\n", self);
        // Wait for the child process to finish
        if (wait(&wstatus) == -1) {
            perror("wait failed");
            return 1;
        }

        sleep(3);

        printf("Parent process: child process exited with status %d\n", wstatus);
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