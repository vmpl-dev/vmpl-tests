#include <check.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/msg.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <vmpl/vmpl.h>

#include "benchmark.h"

START_TEST(test_socket)
{
    int ret = 0;
    pid_t server_pid = fork();
    if (server_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (server_pid == 0) {
        // Child process
        bind_cpu(THREAD_1_CORE);
        ret = vmpl_server(1, NULL);
    } else {
        // Parent process
        sleep(SLEEP_TIME); // Wait for server to start
        pid_t client_pid = fork();
        if (client_pid == -1) {
            perror("fork");
            kill(server_pid, SIGTERM);
            exit(EXIT_FAILURE);
        } else if (client_pid == 0) {
            // Child process
            bind_cpu(THREAD_2_CORE);
            ret = vmpl_client(1, NULL);
        } else {
            // Parent process
            int status;
            waitpid(client_pid, &status, 0);
            if (WIFEXITED(status)) {
                printf("Client exited with status %d\n", WEXITSTATUS(status));
            } else {
                printf("Client exited with signal %d\n", WTERMSIG(status));
            }
            waitpid(server_pid, &status, 0);
            if (WIFEXITED(status)) {
                printf("Server exited with status %d\n", WEXITSTATUS(status));
            } else {
                printf("Server exited with signal %d\n", WTERMSIG(status));
            }
        }
    }
    exit(EXIT_SUCCESS);
}
END_TEST

sem_t sem;

void* sem_thread_func(void* arg) {
    bind_cpu(THREAD_1_CORE);
    printf("Thread waiting on semaphore...\n");
    sem_wait(&sem);
    printf("Thread got semaphore!\n");
    return NULL;
}

void* sem_post_func(void* arg) {
    bind_cpu(THREAD_2_CORE);
    sleep(SLEEP_TIME);
    printf("Posting to semaphore...\n");
    sem_post(&sem);
    return NULL;
}

START_TEST(test_sem)
{
    pthread_t thread1, thread2;
    pthread_attr_t attr;

    printf("Initializing semaphore...\n");
    sem_init(&sem, 0, 0);

    printf("Creating threads...\n");
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_create(&thread1, &attr, sem_thread_func, NULL);
    pthread_create(&thread2, &attr, sem_post_func, NULL);

    printf("Waiting for threads to finish...\n");
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    printf("Destroying semaphore...\n");
    sem_destroy(&sem);

    printf("Done!\n");
}
END_TEST

START_TEST(test_pipe)
{
    int pipefd[2];
    pid_t cpid;
    char buf;

    printf("Creating pipe...\n");
    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(EXIT_FAILURE);
    }

    cpid = fork();
    if (cpid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (cpid == 0) {    /* Child reads from pipe */
        printf("Child pipe process\n");
        close(pipefd[1]);          /* Close unused write end */

        while (read(pipefd[0], &buf, 1) > 0)
            write(STDOUT_FILENO, &buf, 1);

        write(STDOUT_FILENO, "\n", 1);
        close(pipefd[0]);
        _exit(EXIT_SUCCESS);

    } else {            /* Parent writes argv[1] to pipe */
        printf("Parent pipe process\n");
        close(pipefd[0]);          /* Close unused read end */
        write(pipefd[1], "test", 4);
        close(pipefd[1]);          /* Reader will see EOF */
        wait(NULL);                /* Wait for child */
        exit(EXIT_SUCCESS);
    }
}
END_TEST

#define SHM_SIZE 1024

START_TEST(test_shm)
{
    int shmid;
    key_t key;
    pid_t pid1, pid2;
    char *shm;

    // 创建共享内存
    key = ftok(".", 's');
    shmid = shmget(key, SHM_SIZE, IPC_CREAT | 0666);
    if (shmid < 0) {
        perror("shmget");
        exit(1);
    }

    // 创建子进程1
    pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        exit(1);
    } else if (pid1 == 0) {
        // 子进程1
        bind_cpu(THREAD_1_CORE);
        shm = shmat(shmid, NULL, 0);
        if (shm == (char *) -1) {
            perror("shmat");
            exit(1);
        }
        printf("shm: %p\n", shm);
        printf("Write to shm\n");
        sprintf(shm, "Hello, world!");
        printf("shm: %s\n", shm);
        shmdt(shm);
        exit(0);
    }

    sleep(SLEEP_TIME); // Wait for child to start

    // 创建子进程2
    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        exit(1);
    } else if (pid2 == 0) {
        // 子进程2
        bind_cpu(THREAD_2_CORE);
        shm = shmat(shmid, NULL, 0);
        if (shm == (char *) -1) {
            perror("shmat");
            exit(1);
        }
        printf("shm: %p\n", shm);
        printf("Read from shm\n");
        printf("shm: %s\n", shm);
        shmdt(shm);
        exit(0);
    }

    // 等待子进程结束
    waitpid(pid1, NULL, 0);
    waitpid(pid2, NULL, 0);

    // 删除共享内存
    shmctl(shmid, IPC_RMID, NULL);

}
END_TEST

#define MSG_SIZE 1024

struct msgbuf_t {
    long mtype;             /* message type, must be > 0 */
    char mtext[MSG_SIZE];   /* message data */
};

START_TEST(test_msg)
{
    int msqid;
    key_t key;
    struct msgbuf_t buf;
    pid_t pid1, pid2;

    // 创建消息队列
    key = ftok(".", 'm');
    msqid = msgget(key, IPC_CREAT | 0666);
    if (msqid < 0) {
        perror("msgget");
        exit(1);
    }

    // 创建子进程1
    pid1 = fork();
    if (pid1 < 0) {
        perror("fork");
        exit(1);
    } else if (pid1 == 0) {
        // 子进程1
        bind_cpu(THREAD_1_CORE);
        if (msgrcv(msqid, &buf, MSG_SIZE, 1, 0) < 0) {
            perror("msgrcv");
            exit(1);
        }
        printf("Received message: %s\n", buf.mtext);
        exit(0);
    }

    sleep(SLEEP_TIME); // Wait for child to start

    // 创建子进程2
    pid2 = fork();
    if (pid2 < 0) {
        perror("fork");
        exit(1);
    } else if (pid2 == 0) {
        // 子进程2
        bind_cpu(THREAD_2_CORE);
        buf.mtype = 1;
        sprintf(buf.mtext, "Hello, world!");
        if (msgsnd(msqid, &buf, sizeof(buf.mtext), IPC_NOWAIT) < 0) {
            perror("msgsnd");
            exit(1);
        }
        exit(0);
    }

    // 等待子进程结束
    waitpid(pid1, NULL, 0);
    waitpid(pid2, NULL, 0);

    // 删除消息队列
    msgctl(msqid, IPC_RMID, NULL);
}
END_TEST

void handle_sigint(int sig)
{
    printf("Caught signal %d\n", sig);
    exit(EXIT_SUCCESS);
}

START_TEST(test_signal)
{
    signal(SIGINT, handle_sigint);
    printf("Press Ctrl-C to exit\n");
    getchar();
}
END_TEST

Suite *ipc_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Inter-Process Communication");

    /* Core test case */
    tc_core = tcase_create("IPC");
    tcase_add_test(tc_core, test_socket);
    tcase_add_test(tc_core, test_pipe);
    tcase_add_test(tc_core, test_sem);
    tcase_add_test(tc_core, test_msg);
    tcase_add_test(tc_core, test_shm);
    tcase_add_test(tc_core, test_signal);

    suite_add_tcase(s, tc_core);

    return s;
}
