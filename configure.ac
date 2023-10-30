AC_INIT([hello_world], [0.1], [maintainer@example.com])
AM_INIT_AUTOMAKE

# Checks for programs
AC_PROG_CC([musl-gcc])
AC_PROG_CXX([musl-g++])
AC_PROG_INSTALL
AC_PROG_RANLIB

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])

AC_CHECK_HEADERS([argp.h], [AC_DEFINE([HAVE_ARGP], [1], [Have argp])], [])
AC_CHECK_LIB([argp], [argp_parse], [AC_DEFINE([USE_ARGP], [1], [Use argp])], [AC_MSG_WARN([libargp not found, argp support disabled])])
AC_CHECK_LIB([seccomp], [seccomp_init], [AC_DEFINE([USE_SECCOMP], [1], [Use seccomp])], [AC_MSG_WARN([libseccomp not found, seccomp support disabled])])

AC_OUTPUT