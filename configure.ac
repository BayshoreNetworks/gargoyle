#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT(gargoyle_pscand, 1.5, support@bayshorenetworks.com)
AC_CONFIG_SRCDIR([main_daemon.cpp])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_HEADERS([config.h])

# Checks for programs
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET

# Checks for libraries
AC_CHECK_LIB([sqlite3], [main])
AC_CHECK_LIB([netfilter_log], [main])
AC_CHECK_LIB([rt], [main])
AC_CHECK_LIB([pthread], [main])


# Checks for header files
AC_CHECK_HEADERS([errno.h ctype.h signal.h string.h stdlib.h syslog.h unistd.h netinet/in.h netinet/ip.h])

# Checks for typedefs, structures, and compiler characteristics
AC_CHECK_HEADER_STDBOOL
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([strchr strstr malloc free atoi snprintf strncat strtok_r])

AC_ARG_WITH([libpcre],
	    	[  --with-libpcre	Use libpcrecpp for regular expressions],
		[AC_DEFINE([USE_LIBPCRECPP],[1],[Use libpcrecpp])],
		[enable_pcrecpp=yes])

AM_CONDITIONAL([ENABLE_LIBPCRECPP], [test "$enable_pcrecpp"="yes"])
 

GARG_CPPFLAGS="-std=c++11 -Ilib"

AC_SUBST([AM_CXXFLAGS], [-std=c++11])
AC_SUBST([ENABLE_LIBPCRECPP])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
