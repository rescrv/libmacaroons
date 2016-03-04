#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([libmacaroons], [0.4.dev], [robert@rescrv.net])
m4_define([serial_tests], [
    m4_esyscmd([case `automake --version | head -n 1` in
                *1.11*);;
                *) echo serial-tests;;
                esac])
])
AM_INIT_AUTOMAKE(foreign serial_tests subdir-objects dist-bzip2)
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AM_PATH_PYTHON([2.6])
LT_PREREQ([2.2])
LT_INIT
AC_CONFIG_SRCDIR([macaroons.h])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX

ANAL_WARNINGS

# Checks for libraries.
AC_CHECK_FUNC([strlcpy],[BSDLIB=],[BSDLIB=-lbsd])
AC_SUBST([BSDLIBS], [$BSDLIB])

# Checks for header files.
AC_CHECK_HEADER([libutil.h],[AC_DEFINE([HAVE_LIBUTIL_H],[1],[Define to 1 if you have the <libutil.h> header file.])],,)
AC_CHECK_HEADER([bsd/stdlib.h],[AC_DEFINE([HAVE_BSD_STDLIB_H],[1],[Define to 1 if you have the <bsd/stdlib.h> header file.])],,)
AC_CHECK_HEADER([bsd/libutil.h],[AC_DEFINE([HAVE_BSD_LIBUTIL_H],[1],[Define to 1 if you have the <bsd/libutil.h> header file.])],,)

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.

# Optional components
AC_ARG_ENABLE([python_bindings], [AS_HELP_STRING([--enable-python-bindings],
              [build Python bindings @<:@default: no@:>@])],
              [python_bindings=${enableval}], [python_bindings=no])
if test x"${python_bindings}" = xyes; then
    AC_PYTHON_DEVEL([>= '2.6'])
    AS_CASE([$PYTHON_VERSION], [3*], [pythonsym=PyInit_], [2*], [pythonsym=init], [])
    AC_SUBST([PYTHON_SYMBOL], [${pythonsym}])
fi

AM_CONDITIONAL([ENABLE_PYTHON_BINDINGS], [test x"${python_bindings}" = xyes])

AH_BOTTOM([#include <custom-config.h>])
AC_CONFIG_FILES([Makefile
                 libmacaroons.pc])
AC_OUTPUT
