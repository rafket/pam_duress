# pam_duress
A pam module written in C for duress codes in linux authentication

## Compilation

gcc -fPIC -fno-stack-protector -c -I/usr/local/ssl/include pam_duress.c

sudo gcc -shared pam_duress.o -o /lib/security/duress.so -L/usr/local/ssl/lib -lcrypto
