AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

# Specify the include directories for vmpl library
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -g -MD -O2 -z noexecstack
AM_LDFLAGS =

# Specify the target and source files for the myapp project
# Specify the linker flags and the libraries
bin_PROGRAMS = benchmark hello fork timetest test test_sandbox

if USE_CHECK
benchmark_SOURCES = src/tests.c \
                    src/server.c src/client.c \
                    src/bench/bench_dune_ring.c \
                    src/semaphore_test.c \
                    src/test_mxml.c \
                    src/test_zlib.c \
                    src/test_bitmap.c
benchmark_LDFLAGS = 
benchmark_LDADD = -lvmpl -lpthread -lmxml -lz -lcheck
else
benchmark_SOURCES = src/benchmark.c \
                    src/server.c src/client.c \
                    src/bench/bench_dune_ring.c \
                    src/semaphore_test.c \
                    src/test_mxml.c \
                    src/test_zlib.c \
                    src/test_bitmap.c

benchmark_LDFLAGS = 
benchmark_LDADD = -lvmpl -lpthread -lmxml -lz
endif

hello_SOURCES = src/hello.c
hello_LDFLAGS = 
hello_LDADD = -lvmpl

fork_SOURCES = src/fork.c
fork_LDFLAGS = 
fork_LDADD = -lvmpl -lpthread

timetest_SOURCES = src/timetest.c
timetest_LDFLAGS = 
timetest_LDADD = -lvmpl -lpthread

test_SOURCES = src/test.c
test_LDFLAGS = 
test_LDADD = -lvmpl -lpthread

test_sandbox_SOURCES = src/test_sandbox.c
test_sandbox_LDFLAGS =  -pthread