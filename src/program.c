#include <asm/prctl.h>
#include <stdio.h>
#include <stdlib.h>

int test_program() {
    unsigned long fs_reg_value;
    unsigned long gs_reg_value;

    int ret_fs = arch_prctl(ARCH_GET_FS, &fs_reg_value);
    int ret_gs = arch_prctl(ARCH_GET_GS, &gs_reg_value);

    if (ret_fs == 0) {
        printf("FS segment register value: 0x%lx\n", fs_reg_value);
    } else {
        printf("Failed to get FS segment register value\n");
    }

    if (ret_gs == 0) {
        printf("GS segment register value: 0x%lx\n", gs_reg_value);
    } else {
        printf("Failed to get GS segment register value\n");
    }

    return 0;
}
