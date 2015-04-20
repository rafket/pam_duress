# pam_duress
A pam module written in C for duress codes in linux authentication.
Using this pam module, you can set up for any user as many (duress codes)[http://en.wikipedia.org/wiki/Duress_code] as you want.

## Configuration

In order to use this module, you need to add it in one of the files in /etc/pam.d/ (for example in common-auth). You need to be carefull on how you will add it so that it works properly. It is recommended that you put it in the primary block, right after the normal authentication module. It catches the last given password so in case the first module returns an authentication error, the authentication token goes right into the pam_duress module.
Be sure to learn how the pam configuration files are structured so that the module works correctly.

## Compilation

```
gcc -fPIC -fno-stack-protector -c -I/usr/local/ssl/include pam_duress.c

sudo gcc -shared pam_duress.o -o /lib/security/pam_duress.so -L/usr/local/ssl/lib -lcrypto
```
