SHELL := /bin/bash
CC = gcc
PREFIX ?= /usr
CFLAGS = -fPIC -fno-stack-protector -c -I/usr/local/ssl/include -DHASH_ROUNDS=1000 -DDB_PATH='"$(PREFIX)/share/duress"'
LDFLAGS = -L/usr/local/ssl/lib -lcrypto
TARGET = $(DESTDIR)$(PREFIX)

.PHONY: clean install remove

all: adduser deluser pam_duress

pam_duress: pam_duress.c
	$(CC) $(CFLAGS) pam_duress.c
	$(CC) $(LDFLAGS) -shared pam_duress.o -o pam_duress.so

adduser: adduser.c
	$(CC) $(CFLAGS) adduser.c
	$(CC) $(LDFLAGS) adduser.o -o adduser

deluser: deluser.c
	$(CC) $(CFLAGS) deluser.c
	$(CC) $(LDFLAGS) deluser.o -o deluser

install: pam_duress adduser deluser
	if [ -e "$(TARGET)/lib/x86_64-linux-gnu/security" ]; then \
		install -m 744 pam_duress.so $(TARGET)/lib/x86_64-linux-gnu/security/pam_duress.so; \
	else \
		if [ ! -e $(TARGET)/lib/security ]; then \
			mkdir $(TARGET)/lib/security; \
		fi; \
		install -m 744 pam_duress.so $(TARGET)/lib/security/pam_duress.so; \
	fi
	install -m 755 decoyscripts.sh $(TARGET)/bin/pam_duress_decoyscripts
	install -m 755 deluser $(TARGET)/bin/pam_duress_deluser
	install -m 755 adduser $(TARGET)/bin/pam_duress_adduser
	if [ ! -e $(TARGET)/share/duress ]; then \
		mkdir $(TARGET)/share/duress; \
		chmod 777 $(TARGET)/share/duress; \
	fi
	if [ ! -e $(TARGET)/share/duress/hashes ]; then \
		touch $(TARGET)/share/duress/hashes; \
	fi
	if [ ! -e $(TARGET)/share/duress/actions ]; then \
		mkdir $(TARGET)/share/duress/actions; \
		chmod 777 $(TARGET)/share/duress/actions; \
	fi

remove:
	[ ! -e $(TARGET)/lib/security/pam_duress.so ] || rm -v  $(TARGET)/lib/security/pam_duress.so
	[ ! -e $(TARGET)/lib/x86_64-linux-gnu/security/pam_duress.so ] || rm -v  $(TARGET)/lib/x86_64-linux-gnu/security/pam_duress.so
	rm -v  $(TARGET)/bin/pam_duress_decoyscripts
	rm -v  $(TARGET)/bin/pam_duress_adduser
	rm -v  $(TARGET)/bin/pam_duress_deluser
	rm -vr $(TARGET)/share/duress

clean:
	rm -v pam_duress.o pam_duress.so adduser.o adduser
