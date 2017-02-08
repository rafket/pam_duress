SHLIB_NAME=	pam_multipassword.so
SRCS=	pam_duress.c

CFLAGS+=-DHASH_ROUNDS=1000

WARNS=	7

DPADD=	${LIBCRYPTO}
LDADD=	-lcrypto

.include <bsd.lib.mk>
