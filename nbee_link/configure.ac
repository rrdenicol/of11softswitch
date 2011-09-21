                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)

AC_INIT([libnbeelink], [1.00], [<rdenicol@cpqd.com.br>])
AM_INIT_AUTOMAKE

AC_CONFIG_HEADERS([config.h])

# Compile only as shared library.
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
#AC_PROG_RANLIB

# Checks for libraries.
AC_CHECK_LIB(nbee,nbGetLastError)

# Checks for header files.
AC_HEADER_STDC

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T

#AC_SEARCH_LIBS(crypt,[crypt])

# Checks for library functions.
#AC_FUNC_MALLOC

# Output configuration files.
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
