PREFIX=		/usr/local
LIB=		pam_tmphome
SHLIB_NAME=	${LIB}.so.${SHLIB_MAJOR}
SHLIB_MAJOR=	2
SRCS=		${LIB}.c
LIBDIR=		${PREFIX}/lib

.include <bsd.lib.mk>
