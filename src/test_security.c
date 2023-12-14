#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <vmpl/vmpl.h>
#include <vmpl/seimi.h>

#include "benchmark.h"

#ifdef USE_SECCOMP
#include <seccomp.h> /* libseccomp */
START_TEST(test_seccomp)
{
    VMPL_ENTER;
    printf("step 1: unrestricted\n");

    // Init the filter
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL); // default action: kill

    // setup basic whitelist
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);

    // setup our rule
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(dup2), 2,
                        SCMP_A0(SCMP_CMP_EQ, 1),
                        SCMP_A1(SCMP_CMP_EQ, 2));

    // build and load the filter
    seccomp_load(ctx);
    printf("step 2: only 'write' and dup2(1, 2) syscalls\n");

    // Redirect stderr to stdout
    dup2(1, 2);
    printf("step 3: stderr redirected to stdout\n");

    // Duplicate stderr to arbitrary fd
    dup2(2, 42);
    printf("step 4: !! YOU SHOULD NOT SEE ME !!\n");

    // Success (well, not so in this case...)
}
END_TEST
#endif

START_TEST(test_seimi)
{
    VMPL_ENTER;
    char *seimi_user;

    // Allocate 4096 bytes of memory
    seimi_user = sa_alloc(4096, false, NULL);
    sprintf(seimi_user, "Hello, world!");

    // Print the address of seimi_user
    printf("seimi_user: %s\n", seimi_user);

    // Now, we enter VMPL mode
    printf("seimi_user[vmpl]: %p\n", seimi_user);

    // Write to seimi_user (protected)
    __asm__ volatile("stac\n");
    sprintf(seimi_user, "Hello, SEIMI!");
    printf("seimi_user: %s\n", seimi_user);
    __asm__ volatile("clac\n");

    sa_free(seimi_user, 4096);
}
END_TEST

START_TEST(test_seimi_ro)
{
    VMPL_ENTER;
    char *seimi_user, *seimi_super;
    long offset;

    // Allocate 4096 bytes of memory
    seimi_user = sa_alloc(4096, true, &offset);
    seimi_super = seimi_user + offset;
    sprintf(seimi_user, "Hello, world!");

    // Print the addresses of seimi_user and seimi_super
    printf("seimi_user: %s\n", seimi_user);
    printf("seimi_super: %s\n", seimi_super);
    printf("offset: %lx\n", offset);

    // Now, we enter VMPL mode
    printf("seimi_user[vmpl]: %p\n", seimi_user);
    printf("seimi_super[vmpl]: %p\n", seimi_super);

    // Write to seimi_user (protected)
    __asm__ volatile("stac\n");
    sprintf(seimi_user, "Hello, SEIMI!");
    printf("seimi_user: %s\n", seimi_user);
    __asm__ volatile("clac\n");

    // Read from seimi_super (read-only)
    printf("seimi_super: %s\n", seimi_super);

    sa_free(seimi_user, 4096);

}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");

    /* Core test case */
    tc_core = tcase_create("Security");

#ifdef USE_SECCOMP
    tcase_add_test(tc_core, test_seccomp);
#endif
    tcase_add_test(tc_core, test_seimi);
    // tcase_add_test(tc_core, test_seimi_ro);

    suite_add_tcase(s, tc_core);

    return s;
}