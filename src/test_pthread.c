#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void* thread_func(void* arg) {
    printf("Child thread is running...\n");
    sleep(1);
    printf("Child thread is exiting...\n");
    return NULL;
}

int main() {
    int arg = 1;
    void* status;
    pthread_t thread;
    pthread_attr_t attrs;
    pthread_attr_init(&attrs);
    if (pthread_create(&thread, &attrs, thread_func, &arg) != 0)
    {
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
    if (pthread_join(thread, &status) != 0) {
        perror("pthread_join");
        return EXIT_FAILURE;
    }

    if (status == PTHREAD_CANCELED) {
        printf("Child thread was cancelled.\n");
    } else {
        printf("Child thread exited with status %p.\n", status);
    }

    return EXIT_SUCCESS;
}