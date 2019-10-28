SHLIB_NAME=	pam_multipassword.so
SRCS=	pam_duress.c

CFLAGS+=-DHASH_ROUNDS=1000 -DDB_PATH='"/var/db/multipassword"'

WARNS=	9

DPADD=	${LIBCRYPTO}
LDADD=	-lcrypto

.include <bsd.lib.mk>
