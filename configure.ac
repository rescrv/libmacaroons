#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])
AC_INIT([libmacaroons], [0.2.dev], [robert@rescrv.net])
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
PKG_CHECK_MODULES([SODIUM], [libsodium >= 0.4])

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.

# Optional components
AC_ARG_ENABLE([python_bindings], [AS_HELP_STRING([--enable-python-bindings],
              [build Python bindings @<:@default: no@:>@])],
              [python_bindings=${enableval}], [python_bindings=no])
if test x"${python_bindings}" = xyes; then
    AC_PYTHON_DEVEL([>= '2.6'])
fi

AC_ARG_ENABLE([json_support], [AS_HELP_STRING([--enable-json-support],
              [enable support for JSON macaroons @<:@default: no@:>@])],
              [json_support=${enableval}], [json_support=no])
if test x"${json_support}" = xyes; then
    AC_DEFINE([MACAROONS_JSON_SUPPORT], [], [Support JSON macaroons])
    AC_CHECK_LIB([json], [json_object_get_double], [needs_json=yes], [needs_json=no])
    AC_CHECK_LIB([json-c], [json_object_get_double], [needs_json_c=yes], [needs_json_c=no])

    if test x"${needs_json}" = xyes; then
        AC_SUBST([JSON_LIBS], ["-ljson"])
    elif test  x"${needs_json_c}" = xyes; then
        AC_SUBST([JSON_LIBS], ["-ljson-c"])
    else
        AC_MSG_ERROR([
----------------------------------------
Macaroons rely upon the libjson library.
Please install libjson to continue.
----------------------------------------])
    fi

    AC_CHECK_HEADER([json/json.h],,[AC_MSG_ERROR([
----------------------------------------
Macaroons rely upon the libjson library.
Please install libjson to continue.
----------------------------------------])])
fi

AM_CONDITIONAL([ENABLE_PYTHON_BINDINGS], [test x"${python_bindings}" = xyes])
AM_CONDITIONAL([ENABLE_JSON_SUPPORT], [test x"${json_support}" = xyes])

AH_BOTTOM([#include <custom-config.h>])
AC_CONFIG_FILES([Makefile
                 libmacaroons.pc])
AC_OUTPUT
