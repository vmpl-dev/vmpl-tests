#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>
#include <vmpl/vmpl.h>

#include "benchmark.h"

static sem_t sem;

static void* thread_func(void* arg) {
    printf("Thread waiting on semaphore...\n");
    sem_wait(&sem);
    printf("Thread got semaphore!\n");
    return NULL;
}

static void* post_func(void* arg) {
    sleep(2);
    printf("Posting to semaphore...\n");
    sem_post(&sem);
    return NULL;
}

int test_semaphore(int argc, char *argv[]) {
    pthread_t thread1, thread2;

    sem_init(&sem, 0, 0);

    pthread_create(&thread1, NULL, thread_func, NULL);
    pthread_create(&thread2, NULL, post_func, NULL);

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    sem_destroy(&sem);

    return 0;
}