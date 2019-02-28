AC_INIT([pam_module.c])

AC_PREFIX_DEFAULT([/]) 

AC_PROG_CC 
AC_LANG_C 
AC_PROG_MAKE_SET 
AC_PROG_INSTALL 
AC_HEADER_STDC 

AC_CHECK_HEADER(security/pam_appl.h,[], [AC_MSG_ERROR([Couldn't find or include  PAM headers. You may need to install 'pam-devel' with your package manager, or download, compile and install PAM])])

dnl read Makefile.in and write Makefile 
AC_OUTPUT(Makefile)

