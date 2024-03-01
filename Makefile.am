AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4
AM_OBJDIR = .obj

# Specify the include directories for vmpl library
AM_CPPFLAGS = -I$(top_srcdir)/include
AM_CFLAGS = -Wall -g -MD -O3 -z noexecstack
AM_LDFLAGS = -L. -lvmpl -lhotcalls -ldict

# Specify the target and source files for the myapp project
# Specify the linker flags and the libraries
bin_PROGRAMS = benchmark
benchmark_SOURCES = src/benchmark.c \
                    src/server.c src/client.c \
                    src/test_sys.c \
                    src/test_proc.c \
                    src/test_signal.c \
                    src/test_sem.c \
                    src/test_ipc.c \
                    src/test_mem.c \
                    src/test_vdso.c \
                    src/test_security.c \
                    src/test_misc.c \
                    src/test_bitmap.c
benchmark_LDADD = -lvmpl -lpthread -lz -lcheck -lhotcalls -ldict

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