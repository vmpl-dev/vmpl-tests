AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = -I m4

# Specify the include directories for vmpl library
AM_CPPFLAGS = -I$(top_srcdir)/include -I../libvmpl/include -I../svsm-dev
AM_CFLAGS = -Wall -g -MD -O2 -z noexecstack
AM_LDFLAGS = -L/usr/local/lib

# Specify the target and source files for the myapp project
# Specify the linker flags and the libraries
bin_PROGRAMS = vmpl_process hello
vmpl_process_SOURCES = src/vmpl-process.c src/my-device.c src/program.c src/args.c
vmpl_process_LDFLAGS = -static
vmpl_process_LDADD = -L/usr/local/lib -lvmpl

hello_SOURCES = src/hello.c
hello_LDFLAGS = -static
hello_LDADD = -L/usr/local/lib -lvmpl