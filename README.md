# pam\_duress
A pam module written in C for duress codes in linux authentication.
Using this pam module, you can set up for any user as many [duress codes](http://en.wikipedia.org/wiki/Duress_code) as you want.
Basically what it does is if you access your account using a particular password, a script is run (so you can erase all your files if you are caught by the NSA for example...)
This project was inspired by [pam\_confused](https://code.google.com/p/confused/), but since that was written in python and was quite outdated (to the point of being unusable for me), I decided to write a similar pam module in C.

## Configuration

### common-auth et cetera
In order to use this module, you need to add it in one of the files in /etc/pam.d/ (for example in common-auth). You need to be carefull on how you will add it so that it works properly. It is recommended that you put it in the primary block, right after the normal authentication module. It catches the last given password so in case the first module returns an authentication error, the authentication token goes right into the pam\_duress module.
Be sure to learn how the pam configuration files are structured so that the module works correctly.

For example, the primary block of my common-auth, before configuring it for this module was:

```
# here are the per-package modules (the "Primary" block)
auth	[success=2 default=ignore]	pam_unix.so nullok_secure
auth	[success=1 default=ignore]	pam_winbind.so krb5_auth krb5_ccache_type=FILE cached_login try_first_pass
```

The problem is that `success=2` and `success=1` mean to skip the next two or one modules (respectively). So when I added the module I had to change that as well:

```
# here are the per-package modules (the "Primary" block)
auth	[success=3 default=ignore]	pam_unix.so nullok_secure
auth	[success=2 default=ignore]	pam_winbind.so krb5_auth krb5_ccache_type=FILE cached_login try_first_pass
auth    sufficient                      duress.so
```

So I changed these values so that if the first two modules succeed, the duress module is not called, but if those two fail, the duress module is `sufficient` to provide authentication.

If you want your configuration so that the duress module does not provide authentication, change the return value of `pam_sm_authenticate` to always be `PAM_AUTH_ERR`.

### Adding a user-password combination

Each user can have as many duress passwords as he/she wants, and each one with a different script to be run on startup. Each user/password combination is concatinated and the SHA256 of this user-password concatination is written in `/usr/share/duress/hashes`. The structure of this file is a hash in hexadecimal format per line. I will write a script to automatically make entries on this file but for now you can do it manually by obtaining the hash using `echo -n 'yourusernameandpassword' | sha256sum`.

### Creating a script

Scripts for each hash are located at `/usr/share/duress/<hashgoeshere>/script` where this is supposed to be executable by root. Beware that this will be run as root, so many things will not work, while others can be dangerous. Since the permissions under `usr/share/` are `-rw-r--r--`, you need to chmod your scripts so that they become `-rwxr--r--`. I will also write a script for this procedure.

## Compilation

```
gcc -fPIC -fno-stack-protector -c -I/usr/local/ssl/include pam_duress.c
sudo gcc -shared pam_duress.o -o /lib/security/pam_duress.so -L/usr/local/ssl/lib -lcrypto
```
