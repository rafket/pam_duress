CC = gcc
CFLAGS = -fPIC -fno-stack-protector -c -I/usr/local/ssl/include

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
	fi
	if [ ! -e /usr/share/duress/hashes ]; then \
		touch /usr/share/duress/hashes; \
	fi
	if [ ! -e /usr/share/duress/scripts ]; then \
		mkdir /usr/share/duress/scripts; \
		chmod -R 745 /usr/share/duress/scripts; \
	fi
clean:
	rm pam_duress.o
