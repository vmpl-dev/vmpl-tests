AC_INIT([hello_world], [0.1], [maintainer@example.com])
AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])

# Checks for programs
AC_PROG_CC([musl-gcc])
AC_PROG_CXX([musl-g++])
AC_PROG_INSTALL
AC_PROG_RANLIB

AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_ENABLE([debug],
              [AS_HELP_STRING([--enable-debug], [Enable debug mode])],
              [debug=$enableval],
              [debug=no])

AC_CHECK_HEADERS([argp.h], [AC_DEFINE([HAVE_ARGP], [1], [Have argp])], [])
# Checks for typedefs, structures, and compiler characteristics
AC_CHECK_LIB([argp], [argp_parse], [AC_DEFINE([USE_ARGP], [1], [Use argp])], [AC_MSG_WARN([libargp not found, argp support disabled])])
AC_CHECK_LIB([seccomp], [seccomp_init], [AC_DEFINE([USE_SECCOMP], [1], [Use seccomp])], [AC_MSG_WARN([libseccomp not found, seccomp support disabled])])
AC_CHECK_LIB([check], [main], [USE_CHECK=yes], [AC_MSG_WARN([libcheck not found, check support disabled])])
AC_CHECK_LIB([z], [main], [AC_DEFINE([HAVE_ZLIB], [1], [Have zlib])], [AC_MSG_WARN([libz not found, zlib support disabled])])
AC_CHECK_LIB([mxml], [main], [AC_DEFINE([HAVE_MXML], [1], [Have mxml])], [AC_MSG_WARN([libmxml not found, mxml support disabled])])

# Checks for libraries
AM_CONDITIONAL([HAVE_ARGP], [test "x$HAVE_ARGP" = x1])
AM_CONDITIONAL([USE_ARGP], [test "x$USE_ARGP" = x1])
AM_CONDITIONAL([USE_SECCOMP], [test "x$USE_SECCOMP" = x1])
AM_CONDITIONAL([USE_CHECK], [test "x$USE_CHECK" = "xyes" -a "x$debug" = "xyes"])

AC_OUTPUT