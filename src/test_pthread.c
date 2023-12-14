#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void* thread_func(void* arg) {
    while (1) {
        printf("Child thread is running...\n");
        sleep(1);
    }
    return NULL;
}

int main() {
    pthread_t thread;
    if (pthread_create(&thread, NULL, thread_func, NULL) != 0) {
        perror("pthread_create");
        return EXIT_FAILURE;
    }

    sleep(5);  // Let the child thread run for a while

    printf("Main thread is cancelling the child thread.\n");
    if (pthread_cancel(thread) != 0) {
        perror("pthread_cancel");
        return EXIT_FAILURE;
    }

    // Wait for the child thread to terminate
    if (pthread_join(thread, NULL) != 0) {
        perror("pthread_join");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}