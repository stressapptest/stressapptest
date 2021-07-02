AC_PREREQ(2.61)
AC_INIT([stressapptest], [1.0.9_autoconf], [opensource@google.com])

AC_ARG_WITH(static, [  --with-static            enable static linking])

if test "$with_static" = "yes"
then
  AC_MSG_NOTICE([Compiling with staticaly linked libraries.])
  LIBS="$LIBS -static"
else
  AC_MSG_NOTICE([Compiling with dynamically linked libraries.])
fi

AC_CANONICAL_HOST
# Checking for target cpu and setting custom configuration
# for the different platforms
AS_CASE(["$host_cpu"],
  [*x86_64*], [
    AC_DEFINE([STRESSAPPTEST_CPU_X86_64],[],
              [Defined if the target CPU is x86_64])
    ], 
  [*i686*], [
    AC_DEFINE([STRESSAPPTEST_CPU_I686],[],
              [Defined if the target CPU is i686])
    ], 
  [*mips*], [
    AC_DEFINE([STRESSAPPTEST_CPU_MIPS],[],
              [Defined if the target CPU is MIPS])
    ], 
  [*powerpc*], [
    AC_DEFINE([STRESSAPPTEST_CPU_PPC],[],
              [Defined if the target CPU is PowerPC])
    ], 
  [*armv7a*], [
    AC_DEFINE([STRESSAPPTEST_CPU_ARMV7A],[],
              [Defined if the target CPU is armv7a])
    ], 
  [*aarch64*], [
    AC_DEFINE([STRESSAPPTEST_CPU_AARCH64],[],
              [Defined if the target CPU is aarch64])
    ],
[AC_MSG_WARN([Unsupported CPU: $host_cpu! Try x86_64, i686, mips, powerpc, armv7a, or aarch64])]
)

## The following allows like systems to share settings. This is not meant to
## imply that these OS are the same thing. From OpenOffice dmake configure.in
AS_CASE(["$host_os"],
  [*linux*], [
    OS_VERSION=linux
    AC_DEFINE([STRESSAPPTEST_OS_LINUX],[],
              [Defined if the target OS is Linux])
    ],
  [*darwin*], [
    OS_VERSION=macosx
    AC_DEFINE([STRESSAPPTEST_OS_DARWIN],[],
              [Defined if the target OS is OSX])
    ],
  [*freebsd*], [
    OS_VERSION=bsd
    AC_DEFINE([STRESSAPPTEST_OS_BSD],[],
              [Defined if the target OS is BSD based])
    ],
  [*netbsd*], [
    OS_VERSION=bsd
    AC_DEFINE([STRESSAPPTEST_OS_BSD],[],
              [Defined if the target OS is BSD based])
    ],
  [AC_MSG_WARN([unsupported system: $host_os])]
)

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

if test -n "$SOURCE_DATE_EPOCH"
then
  timestamp=$(date -u -d "@$SOURCE_DATE_EPOCH" 2>/dev/null || date -u -r "$SOURCE_DATE_EPOCH" 2>/dev/null || date -u)
  username=reproducible
  hostname=reproducible
fi

AC_DEFINE_UNQUOTED([STRESSAPPTEST_TIMESTAMP],
                   "$username @ $hostname on $timestamp",
                   [Timestamp when ./configure was executed])

AC_ARG_ENABLE([default-optimizations],
    [AS_HELP_STRING([--disable-default-optimizations], [Disable default optimization flag overrides])])
AS_IF([test x"$enable_default_optimizations" != xno], [
    #Default cxxflags
    CXXFLAGS="$CXXFLAGS -DCHECKOPTS"
    CXXFLAGS="$CXXFLAGS -Wreturn-type -Wunused -Wuninitialized -Wall"
    CXXFLAGS="$CXXFLAGS -O3 -funroll-all-loops  -funroll-loops -DNDEBUG"
])

AC_SYS_LARGEFILE

# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
# Skip malloc.h to prevent redefinition of HAVE_MALLOC_H on some platforms
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h], [], [AC_MSG_FAILURE([Missing some header files.])])
AC_CHECK_HEADERS([pthread.h])
AC_SEARCH_LIBS([pthread_create], [pthread])
AC_CHECK_TYPE([pthread_barrier_t], AC_DEFINE(HAVE_PTHREAD_BARRIERS, [1], [Define to 1 if the system has `pthread_barrier'.]))
AC_CHECK_HEADERS([libaio.h])
AC_SEARCH_LIBS([io_setup], [aio])
AC_CHECK_HEADERS([sys/shm.h])
AC_SEARCH_LIBS([shm_open], [rt])


# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_CONST
AC_C_INLINE
AC_TYPE_PID_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_HEADER_TIME
AC_TYPE_UINT16_T
AC_C_VOLATILE


# Checks for library functions.
AC_FUNC_CLOSEDIR_VOID
AC_PROG_GCC_TRADITIONAL
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_STRERROR_R
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([ftruncate gettimeofday memset munmap select socket strtol strtoull])
AC_CHECK_FUNCS([mmap64 posix_memalign rand_r sched_getaffinity])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
