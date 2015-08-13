SHELL = /bin/bash
CC = gcc
CFLAGS = -fPIC -fno-stack-protector -c -I/usr/local/ssl/include
EDITOR = $${FCEDIT:-$${VISUAL:-$${EDITOR:-nano}}}

pam_duress: pam_duress.c
	$(CC) $(CFLAGS) pam_duress.c
install: pam_duress.c
	if [ ! -e /lib/security ]; then \
		mkdir /lib/security; \
	fi
	$(CC) -shared pam_duress.o -o /lib/security/pam_duress.so -L/usr/local/ssl/lib -lcrypto; \
	chmod 744 /lib/security/pam_duress.so
	if [ ! -e /usr/share/duress ]; then \
		mkdir /usr/share/duress; \
                chmod -R 700 /usr/share/duress; \
	fi
	if [ ! -e /usr/share/duress/hashes ]; then \
		touch /usr/share/duress/hashes; \
	fi
	if [ ! -e /usr/share/duress/scripts ]; then \
		mkdir /usr/share/duress/scripts; \
		chmod -R 700 /usr/share/duress/scripts; \
	fi
	$(EDITOR) /etc/pam.d/common-auth;
clean:
	rm pam_duress.o
