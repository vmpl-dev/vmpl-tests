#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "globals.h"
#include "vmpl.h"
#include "procmap.h"
#include "svsm-vmpl.h"
// #include "vc.h"
#include "args.h"

#if 0
static inline int rmpadjust(unsigned long vaddr, bool rmp_psize, unsigned long attrs)
{
	int rc;

	/* "rmpadjust" mnemonic support in binutils 2.36 and newer */
	asm volatile(".byte 0xF3,0x0F,0x01,0xFE\n\t"
		     : "=a"(rc)
		     : "a"(vaddr), "c"(rmp_psize), "d"(attrs)
		     : "memory", "cc");

	return rc;
}

static void grant_vmpl2_access(MemoryMapping *mapping) {
    uint32_t nr_pages;
    uint64_t vaddr;

    switch (get_mapping_type(mapping->pathname)) {
    case PROCMAP_TYPE_UNKNOWN:
    case PROCMAP_TYPE_ANONYMOUS:
    case PROCMAP_TYPE_VSYSCALL:
    case PROCMAP_TYPE_VVAR:
        return;
    default:
        break;
    }

    nr_pages = (mapping->end - mapping->start) >> 12;

    print_mapping_oneline(mapping);
    for (vaddr = mapping->start; vaddr < mapping->end; vaddr += PAGE_SIZE) {
        printf("%lx\n", vaddr);
        rmpadjust(vaddr, RMP_4K, Vmpl2 | VMPL_RWX);
    }
}

static inline void setup_vmpl(void) {
    printf("setup vmpl\n");
    // 调用解析虚拟地址信息函数并传入回调函数
    parse_proc_maps(grant_vmpl2_access);
}
#endif

int main(int argc, char *argv[])
{
    struct arguments arguments;

    arguments.init = 0;
    arguments.enter = 0;

    parse_args(&arguments);

    parse_proc_maps(print_mapping_oneline);

    if (arguments.init) {
      vmpl_init();
      if (arguments.enter) {
          vmpl_enter();
      }
    }

    return 0;
}