AC_PREREQ(2.61)
AC_INIT(stressapptest, 1.0.0_autoconf, opensource@gmail.com)

# Checking for target cpu and setting custom configuration
# for the different platforms
AC_CANONICAL_TARGET
case x"$target_cpu" in
"xx86_64")
  AC_DEFINE([STRESSAPPTEST_CPU_X86_64],[],
	    [Defined if the target CPU is x86_64])
;;
"xi686")
  AC_DEFINE([STRESSAPPTEST_CPU_I686],[],
	    [Defined if the target CPU is i686])
;;
"xpowerpc")
  AC_DEFINE([STRESSAPPTEST_CPU_PPC],[],
	    [Defined if the target CPU is PowerPC])
;;
esac

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADER([src/stressapptest_config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

#Getting user and host info
username=$(whoami)
AC_MSG_CHECKING([user ID])
AC_MSG_RESULT([$username])

hostname=$(uname -n)
AC_MSG_CHECKING([host name])
AC_MSG_RESULT([$hostname])

timestamp=$(date)
AC_MSG_CHECKING([current timestamp])
AC_MSG_RESULT([$timestamp])

AC_DEFINE_UNQUOTED([STRESSAPPTEST_TIMESTAMP],
		   "$username @ $hostname on $timestamp", 
	  	   [Timestamp when ./configure was executed])

#Default cxxflags
CXXFLAGS="$CXXFLAGS -DCHECKOPTS"
CXXFLAGS="$CXXFLAGS -Wreturn-type -Wunused -Wuninitialized -Wall"
CXXFLAGS="$CXXFLAGS -O3 -funroll-all-loops  -funroll-loops -DNDEBUG"

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_C_RESTRICT
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_C_VOLATILE

# Checking for pthreads
pthread_arg="not_available"
AC_MSG_CHECKING([which argument is required to compile pthreads])

pthread_header="#include<pthread.h>"
pthread_body="pthread_create(0,0,0,0)"
# Check if compile with no extra argument
AC_LINK_IFELSE([AC_LANG_PROGRAM($pthread_header, $pthread_body)], 
pthread_arg="")

if test x"$pthread_arg" = x"not_available"; then
  # At first, only -pthread was tested, but this is the place
  # to add extra pthread flags if someone can test them
  bkp_LDFLAGS="$LDFLAGS"
  for altheader in -pthread; do
    LDFLAGS="$bkp_LDFLAGS $altheader"
    AC_LINK_IFELSE([AC_LANG_PROGRAM($pthread_header, $pthread_body)], 
    pthread_arg="$altheader")
    LDFLAGS="$bkp_LDFLAGS"
  done
fi

if test x"$pthread_arg" = x"not_available"; then
   AC_MSG_FAILURE([Cannot find a proper pthread library])
else
   if test x"$pthread_arg" = x; then
     AC_MSG_RESULT([none])
   else
     AC_MSG_RESULT([$pthread_arg])
   fi
   LDFLAGS="$LDFLAGS $pthread_arg"
fi

# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_PROG_GCC_TRADITIONAL
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STRERROR_R
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([gettimeofday memset select socket strtol strtoull])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
