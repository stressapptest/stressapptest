AC_PREREQ(2.61)
AC_INIT(stressapptest, 1.0.3_autoconf, opensource@google.com)

AC_CANONICAL_HOST
AC_CANONICAL_BUILD
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
  "xarmv7a")
    AC_DEFINE([STRESSAPPTEST_CPU_ARMV7A],[],
              [Defined if the target CPU is armv7a])
    ;;
  *)
    AC_MSG_ERROR([$target_cpu is not supported! Try x86_64, i686, powerpc, or armv7a])
    ;;
esac

_os=`uname`
## The following allows like systems to share settings. This is not meant to
## imply that these OS are the same thing. From OpenOffice dmake configure.in
case "$_os" in
  "Linux")
    OS_VERSION=linux
    AC_DEFINE([STRESSAPPTEST_OS_LINUX],[],
              [Defined if the target OS is Linux])
    ;;
  "Darwin")
    OS_VERSION=macosx
    AC_DEFINE([STRESSAPPTEST_OS_DARWIN],[],
              [Defined if the target OS is OSX])
    ;;
  "FreeBSD")
    OS_VERSION=bsd
    AC_DEFINE([STRESSAPPTEST_OS_BSD],[],
              [Defined if the target OS is BSD based])
    ;;
  "NetBSD")
    OS_VERSION=bsd
    AC_DEFINE([STRESSAPPTEST_OS_BSD],[],
              [Defined if the target OS is BSD based])
    ;;
  *)
    AC_MSG_ERROR([$_os operating system is not suitable to build dmake!])
    ;;
esac

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/])
AC_CONFIG_HEADER([src/stressapptest_config.h])

# Checks for programs.
#  Don't generate CXXFLAGS defaults: if CXXFLAGS are unset
#  AC_PROG_CXX will override them with unwanted defaults.
CXXFLAGS="$CXXFLAGS"
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
CXXFLAGS="$CXXFLAGS -Wreturn-type -Wunused -Wuninitialized -Wall -Wno-psabi"
CXXFLAGS="$CXXFLAGS -O3 -funroll-all-loops  -funroll-loops -DNDEBUG"

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h malloc.h netdb.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS([pthread.h libaio.h])

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


# These are the libraries stressapptest requires to build.
# We'll check that they work, and fail otherwise.
# In the future we may provide for testing alternate
# arguments, but that's not necessary now.
LIBS="$LIBS -static -lrt -pthread -laio"

# Checking for pthreads
pthread_arg="not_available"
AC_MSG_CHECKING([if pthreads is supported])

pthread_header="#include<pthread.h>"
pthread_body="pthread_create(0,0,0,0)"
# Check if compile with no extra argument
AC_LINK_IFELSE([AC_LANG_PROGRAM($pthread_header, $pthread_body)],
pthread_arg="")

if test x"$pthread_arg" = x"not_available"; then
  AC_MSG_FAILURE([Cannot find a proper pthread library])
else
  AC_MSG_RESULT([yes])
fi

# Checking for libaio
libaio_arg="not_available"
AC_MSG_CHECKING([if libaio is supported])

libaio_header="#include<libaio.h>"
libaio_body="io_submit(0,0,0)"
# Check if compile with no extra argument
AC_LINK_IFELSE([AC_LANG_PROGRAM($libaio_header, $libaio_body)],
libaio_arg="")

if test x"$libaio_arg" = x"not_available"; then
  AC_MSG_FAILURE([Cannot find libaio library, please install libaio-dev])
else
  AC_MSG_RESULT([yes])
fi

# Checking for librt
librt_arg="not_available"
AC_MSG_CHECKING([if librt is supported])

librt_header="#include<sys/shm.h>"
librt_body="shm_open(0, 0, 0)"
# Check if compile with no extra argument
AC_LINK_IFELSE([AC_LANG_PROGRAM($librt_header, $librt_body)],
librt_arg="")

if test x"$librt_arg" = x"not_available"; then
  AC_MSG_FAILURE([Cannot find librt library])
else
  AC_MSG_RESULT([yes])
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
