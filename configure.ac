#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([lttngtop],[0.2],[julien dot desfossez at efficios dot com])
AC_CONFIG_AUX_DIR([config])
AC_CANONICAL_TARGET
AC_CANONICAL_HOST
AM_INIT_AUTOMAKE([foreign dist-bzip2 no-dist-gzip])
AM_SILENT_RULES([yes])

AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AC_PROG_MAKE_SET
LT_INIT
AC_PROG_YACC
AC_PROG_LEX

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_PID_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_CHECK_FUNCS([bzero gettimeofday munmap strtoul])

# Check for libuuid
AC_CHECK_LIB([uuid], [uuid_generate], [],
	[AC_MSG_ERROR([Cannot find the libuuid library.])]
)

# Check for libpopt
AC_CHECK_LIB([popt], [poptGetContext], [],
        [AC_MSG_ERROR([Cannot find the popt library.])]
)

# Check for libncurses
AC_CHECK_LIB([ncurses], [initscr], [],
	[AC_MSG_ERROR([Cannot find the the ncurses library.])]
)

# Check for libpanel, also part of libncurses
# (but this check will add the required -lpanel flag)
AC_CHECK_LIB([panel], [update_panels], [],
	[AC_MSG_ERROR([Cannot find the the ncurses library.])]
)

# Check for libbabeltrace
AC_CHECK_LIB([babeltrace], [bt_context_create], [],
	     [AC_MSG_ERROR([Cannot find the babeltrace library.])]
	     )

# Check for libbabeltrace-ctf
AC_CHECK_LIB([babeltrace-ctf], [bt_ctf_iter_create], [],
	     [AC_MSG_ERROR([Cannot find the babeltrace-ctf library.])]
	     )

# Check for Glib. It needs to be installed anyway or this macro will not be defined.
AM_PATH_GLIB_2_0([2.22.0], [],
	[AC_MSG_ERROR([Glib 2.22 is required in order to compile LTTngTop.
Please install the Glib development files.])], [gmodule]
)

pkg_modules="gmodule-2.0 >= 2.0.0"
PKG_CHECK_MODULES(GMODULE, [$pkg_modules])
AC_SUBST(PACKAGE_LIBS)
LIBS="$LIBS $GMODULE_LIBS"

PACKAGE_CFLAGS="$GMODULE_CFLAGS -Wall -Werror=format-security"
AC_SUBST(PACKAGE_CFLAGS)

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	doc/Makefile
])
AC_OUTPUT
