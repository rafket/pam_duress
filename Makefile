CC = gcc
CFLAGS = -fPIC -fno-stack-protector -c -I/usr/local/ssl/include

pam_duress: pam_duress.c
	$(CC) $(CFLAGS) pam_duress.c
install: pam_duress.c
	sudo $(CC) -shared pam_duress.o -o /lib/security/pam_duress.so -L/usr/local/ssl/lib -lcrypto
clean:
	rm pam_duress.o
