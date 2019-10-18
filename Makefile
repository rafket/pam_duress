SHELL := /bin/bash
CC = gcc
CFLAGS = -fPIC -fno-stack-protector -c -I/usr/local/ssl/include -DHASH_ROUNDS=1000
LDFLAGS = -L/usr/local/ssl/lib -lcrypto
EDITOR = $${FCEDIT:-$${VISUAL:-$${EDITOR:-nano}}}

.PHONY: clean install config remove

all: adduser pam_duress

pam_duress: pam_duress.c
	$(CC) $(CFLAGS) pam_duress.c
	$(CC) $(LDFLAGS) -shared pam_duress.o -o pam_duress.so

adduser: adduser.c
	$(CC) $(CFLAGS) adduser.c
	$(CC) $(LDFLAGS) adduser.o -o adduser

install: pam_duress adduser
	if [ -e "/lib/x86_64-linux-gnu/security" ]; then \
		install -m 744 pam_duress.so /lib/x86_64-linux-gnu/security/pam_duress.so; \
	else \
		if [ ! -e /lib/security ]; then \
			mkdir /lib/security; \
		fi; \
		install -m 744 pam_duress.so /lib/security/pam_duress.so; \
	fi
	chmod +x ./decoyscripts.sh; \
	chmod +x ./deluser.sh; \
	if [ ! -e /usr/share/duress ]; then \
		mkdir /usr/share/duress; \
		chmod -R 777 /usr/share/duress; \
	fi
	if [ ! -e /usr/share/duress/hashes ]; then \
		touch /usr/share/duress/hashes; \
	fi
	if [ ! -e /usr/share/duress/actions ]; then \
		mkdir /usr/share/duress/actions; \
		chmod -R 777 /usr/share/duress/actions; \
	fi

config:
	if  whiptail --yesno "Start decoyscripts.sh to improve plausible deniability?" 10 50 ; then \
		bash decoyscripts.sh $$(( $${RANDOM} % 128 )); \
	fi
	if  whiptail --yesno "Edit /etc/pam.d/common-auth?" 10 50 ; then \
		$(EDITOR) /etc/pam.d/common-auth; \
	fi

remove:
	rm -v /lib/security/pam_duress.so
	rm -v /lib/x86_64-linux-gnu/security/pam_duress.so
	rm -vr /usr/share/duress

clean:
	rm -v pam_duress.o pam_duress.so adduser.o adduser
