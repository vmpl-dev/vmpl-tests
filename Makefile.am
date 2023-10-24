AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

# Specify the include directories for vmpl library
AM_CPPFLAGS = -I$(top_srcdir)/include -I../libvmpl/include -I../svsm-dev
AM_CFLAGS = -Wall -g -MD -O2 -z noexecstack
AM_LDFLAGS = -L/usr/local/lib

# Specify the target and source files for the myapp project
# Specify the linker flags and the libraries
bin_PROGRAMS = vmpl_process hello fork timetest test test_sandbox
vmpl_process_SOURCES = src/vmpl-process.c
vmpl_process_LDFLAGS = -static
vmpl_process_LDADD = -L/usr/local/lib -lvmpl

hello_SOURCES = src/hello.c
hello_LDFLAGS = -static
hello_LDADD = -L/usr/local/lib -lvmpl

fork_SOURCES = src/fork.c
fork_LDFLAGS = -static
fork_LDADD = -L/usr/local/lib -lvmpl -lpthread

timetest_SOURCES = src/timetest.c
timetest_LDFLAGS = -static
timetest_LDADD = -L/usr/local/lib -lvmpl -lpthread

test_SOURCES = src/test.c
test_LDFLAGS = -static
test_LDADD = -L/usr/local/lib -lvmpl -lpthread

test_sandbox_SOURCES = src/test_sandbox.c
test_sandbox_LDFLAGS = -static -pthread