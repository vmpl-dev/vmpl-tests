AC_INIT([hello_world], [0.1], [maintainer@example.com])
AM_INIT_AUTOMAKE([foreign])
AM_SILENT_RULES([yes])

# Checks for programs
AC_PROG_CC([musl-gcc])
AC_PROG_INSTALL
# Set installation prefix
AC_PREFIX_DEFAULT([/usr/local/musl])

LT_INIT([shared static])
AC_CONFIG_HEADERS([include/config.h])
AC_CONFIG_SRCDIR([src])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_MACRO_DIRS([m4])

AC_ARG_ENABLE([debug],
              [AS_HELP_STRING([--enable-debug], [Enable debug mode])],
              [debug=$enableval],
              [debug=no])

AC_CHECK_HEADERS([argp.h], [AC_DEFINE([HAVE_ARGP], [1], [Have argp])], [])
AC_CHECK_HEADERS([seccomp.h], [AC_DEFINE([HAVE_SECCOMP], [1], [Have seccomp])], [])
AC_CHECK_HEADERS([check.h], [AC_DEFINE([HAVE_CHECK], [1], [Have check])], [])
AC_CHECK_HEADERS([zlib.h], [AC_DEFINE([HAVE_ZLIB], [1], [Have zlib])], [])
AC_CHECK_HEADERS([mxml.h], [AC_DEFINE([HAVE_MXML], [1], [Have mxml])], [])

# Checks for typedefs, structures, and compiler characteristics
AC_CHECK_LIB([argp], [argp_parse], [USE_ARGP=1], [AC_MSG_WARN([libargp not found, argp support disabled])])
AC_CHECK_LIB([seccomp], [seccomp_init], [USE_SECCOMP=1], [AC_MSG_WARN([libseccomp not found, seccomp support disabled])])
AC_CHECK_LIB([check], [main], [USE_CHECK=1], [AC_MSG_WARN([libcheck not found, check support disabled])])
AC_CHECK_LIB([z], [compress], [USE_ZLIB=1], [AC_MSG_WARN([libz not found, zlib support disabled])])
AC_CHECK_LIB([mxml], [mxmlLoadFile], [USE_MXML=1], [AC_MSG_WARN([libmxml not found, mxml support disabled])])

# Checks for libraries
AM_CONDITIONAL([USE_ARGP], [test "x$USE_ARGP" = "x1"])
AM_CONDITIONAL([USE_SECCOMP], [test "x$USE_SECCOMP" = "x1"])
AM_CONDITIONAL([USE_CHECK], [test "x$USE_CHECK" = "x1" -a "x$debug" = "xno"])
AM_CONDITIONAL([USE_ZLIB], [test "x$USE_ZLIB" = "x1"])
AM_CONDITIONAL([USE_MXML], [test "x$USE_MXML" = "x1"])

AC_OUTPUT