AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
AM_OBJDIR = .obj

# Specify the include directories for vmpl library
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -g -MD -O2 -z noexecstack
AM_LDFLAGS = 

# Specify the target and source files for the myapp project
# Specify the linker flags and the libraries
bin_PROGRAMS = benchmark hello fork timetest test test_sandbox test_fork xsave xsave_new \
                test_brk \
                test_sbrk \
                test_maps \
                test_pagemap \
                test_spsc \
                test_signal \
                test_pthread

benchmark_SOURCES = src/benchmark.c \
                    src/server.c src/client.c \
                    src/bench/bench_dune_ring.c \
                    src/semaphore_test.c \
                    src/test_sys.c \
                    src/test_proc.c \
                    src/test_ipc.c \
                    src/test_mem.c \
                    src/test_vdso.c \
                    src/test_security.c \
                    src/test_misc.c \
                    src/test_bitmap.c
benchmark_LDADD = -lvmpl -lpthread -lz -lcheck

if USE_ZLIB
benchmark_SOURCES += src/test_zlib.c
benchmark_LDADD += -lz
endif

if USE_MXML
benchmark_SOURCES += src/test_mxml.c
benchmark_LDADD += -lmxml
endif

if USE_SECCOMP
benchmark_LDADD += -lseccomp
endif

hello_SOURCES = src/hello.c
hello_LDADD = -lvmpl

fork_SOURCES = src/fork.c
fork_LDADD = -lpthread

timetest_SOURCES = src/timetest.c
timetest_LDADD = -lpthread

test_SOURCES = src/test.c
test_LDADD = -lvmpl -lpthread

test_sandbox_SOURCES = src/test_sandbox.c
test_sandbox_LDFLAGS = -pthread 
test_sandbox_LDADD = 

test_fork_SOURCES = src/test_fork.c
test_fork_LDFLAGS = -pthread
test_fork_LDADD = -lvmpl

xsave_SOURCES = src/xsave.c

xsave_new_SOURCES = src/xsave-new.c

test_pthread_SOURCES = src/test_pthread.c
test_pthread_LDADD = -lpthread

test_spsc_SOURCES = src/test_spsc.c
test_spsc_LDADD = -lpthread

test_signal_SOURCES = src/test_signal.c
test_signal_LDADD = -lpthread -lcheck

test_brk_SOURCES = src/test_brk.c
test_sbrk_SOURCES = src/test_sbrk.c
test_sbrk_LDFLAGS = -lvmpl -lcheck
test_maps_SOURCES = src/test_maps.c
test_pagemap_SOURCES = src/test_pagemap.c