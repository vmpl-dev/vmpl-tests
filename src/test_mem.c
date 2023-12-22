#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <vmpl/vmpl.h>
#include <vmpl/mm.h>
#include <vmpl/log.h>

#include "benchmark.h"

#define PHYS_ADDR 0x0
#define SIZE 10

START_TEST(test_dev_mem)
{
    int fd;
    void *map_base;
    unsigned char *ptr;

    fd = open("/dev/mem", O_RDONLY);
    ck_assert_msg(fd != -1, "Error opening /dev/mem");

    map_base = mmap(NULL, SIZE, PROT_READ, MAP_SHARED, fd, PHYS_ADDR);
    ck_assert_msg(map_base != MAP_FAILED, "Error mapping memory");

    ptr = (unsigned char *)map_base;
    for (int i = 0; i < SIZE; i++) {
        printf("0x%02x ", ptr[i]);
    }
    printf("\n");

    munmap(map_base, SIZE);
    close(fd);
}
END_TEST

START_TEST(test_mmap)
{
    int fd = open("file.txt", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        perror("mmap");
        close(fd);
    } else {
        printf("mmap: %p\n", addr);
        close(fd);
    }
}
END_TEST

START_TEST(test_munmap)
{
    int fd = open("file.txt", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_ptr_ne(addr, MAP_FAILED);
    printf("addr: %p\n", addr);
    int ret = munmap(addr, 4096);
    ck_assert_int_eq(ret, 0);
    close(fd);
}
END_TEST

START_TEST(test_mprotect)
{
    int fd = open("file.txt", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_ptr_ne(addr, MAP_FAILED);
    printf("addr: %p\n", addr);
    int ret = mprotect(addr, 4096, PROT_READ | PROT_WRITE);
    ck_assert_int_eq(ret, 0);
    close(fd);
}
END_TEST

START_TEST(test_mremap)
{
    int fd = open("file.txt", O_RDONLY);
    void *addr = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE, fd, 0);
    ck_assert_ptr_ne(addr, MAP_FAILED);
    printf("addr: %p\n", addr);
    void *new_addr = mremap(addr, 4096, 8192, MREMAP_MAYMOVE);
    ck_assert_ptr_ne(new_addr, MAP_FAILED);
    printf("new_addr: %p\n", new_addr);
    close(fd);
}
END_TEST

START_TEST(test_sbrk)
{
    void *cur_brk, *tmp_brk = NULL;

    printf("The original program break: %p\n", sbrk(0));

    tmp_brk = sbrk(4096);
    ck_assert_ptr_ne(tmp_brk, (void *)-1);

    cur_brk = sbrk(0);
    printf("The program break after incrementing: %p\n", cur_brk);

    tmp_brk = sbrk(-4096);
    ck_assert_ptr_ne(tmp_brk, (void *)-1);

    cur_brk = sbrk(0);
    printf("The program break after decrementing: %p\n", cur_brk);

}
END_TEST

static void pgflt_handler(struct dune_tf *tf)
{
    int rc, level;
	uint64_t cr2 = read_cr2();
	pte_t *ptep;
	log_warn("dune: page fault at 0x%016lx, error-code = %x", cr2, tf->err);
	rc = lookup_address(cr2, &level, &ptep);
	if (rc != 0) {
		log_err("dune: page fault at unmapped addr 0x%016lx", cr2);
	} else {
		log_warn("dune: page fault at mapped addr 0x%016lx", cr2);
        *ptep |= PTE_PRESENT | PTE_WRITE;
    }
}

START_TEST(test_pgflt)
{
    char *addr_ro;
    addr_ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ck_assert_ptr_ne(addr_ro, MAP_FAILED);

    dune_register_pgflt_handler(pgflt_handler);
    *addr_ro = 1;
}
END_TEST

Suite *vm_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Virtual Memory");

    /* Core test case */
    tc_core = tcase_create("Memory");

    tcase_add_test(tc_core, test_dev_mem);
    tcase_add_test(tc_core, test_mmap);
    tcase_add_test(tc_core, test_munmap);
    tcase_add_test(tc_core, test_mprotect);
    tcase_add_test(tc_core, test_mremap);
    tcase_add_test(tc_core, test_sbrk);
    tcase_add_test_raise_signal(tc_core, test_pgflt, SIGSEGV);

    suite_add_tcase(s, tc_core);

    return s;
}