AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

# Specify the include directories for vmpl library
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -g -MD -O2 -z noexecstack
AM_LDFLAGS = -static

# Specify the target and source files for the myapp project
# Specify the linker flags and the libraries
bin_PROGRAMS = benchmark hello fork timetest test test_sandbox

benchmark_SOURCES = src/server.c src/client.c \
                    src/bench/bench_dune_ring.c \
                    src/semaphore_test.c \
                    src/test_bitmap.c
benchmark_LDFLAGS = -static
benchmark_LDADD = -lvmpl -lpthread -lz

if USE_CHECK
benchmark_SOURCES += src/tests.c
benchmark_LDADD += -lcheck
else
benchmark_SOURCES += src/benchmark.c
endif

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
hello_LDFLAGS = -static
hello_LDADD = -lvmpl

fork_SOURCES = src/fork.c
fork_LDFLAGS = -static
fork_LDADD = -lvmpl -lpthread

timetest_SOURCES = src/timetest.c
timetest_LDFLAGS = -static
timetest_LDADD = -lvmpl -lpthread

test_SOURCES = src/test.c
test_LDFLAGS = -static
test_LDADD = -lvmpl -lpthread

test_sandbox_SOURCES = src/test_sandbox.c
test_sandbox_LDFLAGS = -pthread -static
test_sandbox_LDADD = -lvmpl