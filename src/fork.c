/* CELEBW02

   The following function suspends the calling process using &waitpid.
   until a child process ends.

 */
#define _POSIX_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  pid_t pid;
  time_t t;
  int status;
  if ((pid = fork()) < 0)
    perror("fork() error");
  else if (pid == 0) {
    printf("child pid = %d\n", getpid());
    sleep(5);
    // exit(EXIT_SUCCESS);
  } else
    do {
      if ((pid = waitpid(pid, &status, WNOHANG)) == -1)
        perror("wait() error");
      else if (pid == 0) {
        time(&t);
        printf("child is still running at %s", ctime(&t));
        sleep(1);
        // exit(EXIT_SUCCESS);
      } else {
        if (WIFEXITED(status))
          printf("child exited with status of %d\n", WEXITSTATUS(status));
        else if (WIFSIGNALED(status))
          printf("child terminated abnormally, signal %d\n", WTERMSIG(status));
        else if (WIFSTOPPED(status))
          printf("child stopped, signal %d\n", WSTOPSIG(status));
        else
          printf("child did not exit successfully with exit status %d\n",
                 status);
      }
    } while (pid == 0);

  return 0;
}