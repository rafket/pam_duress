# pam\_duress
A pam module written in C that provides a duress password functionality in Linux authentication.

Basically, a duress code is a fake password that allows the user to issue commands to his computer during login without an observer noticing. The user just has to enter his duress password (that he has set beforehand) and then an alarm is sent than can trigger a variety of actions (for example a mail could be automatically sent from his computer to a rescuer, a script could delete sensitive files in his hard-disk or a certain Rick Astley song could be appropriately played). A situation (albeit somewhat extreme) where this could be useful is described in Cory Doctorow's wonderful book "Little Brother", where the protagonist is forced to provide his credentials to an evil organization, but manages to fool them using a duress password to hide his files.

From [Wikipedia](http://en.wikipedia.org/wiki/Duress_code):

>A duress code is a covert distress signal used by an individual who is being coerced by one or more hostile persons. It is used to warn others that they are being forced to do something against their will. Typically, the warning is given via some innocuous signal embedded in normal communication, such as a code-word or phrase spoken during conversation to alert other personnel. Alternatively, the signal may be incorporated into the authentication process itself, typically in the form of a panic password, distress password, or duress PIN that is distinct from the user's normal password or PIN.

Using this pam module, you can set up for any user as many duress codes as you want.
This project was inspired by [pam\_confused](https://code.google.com/p/confused/), but since that was written in python and was quite outdated (to the point of being unusable for me), I decided to write a similar pam module in C.

## Proof

Both proofs are implemented the same way (the installation does not change), and the only thing that changes is the way that the user uses the module. Because it is supposed to be a duress module, the configuration will refer to the second, unsafe installation with regards to terminology.

### The provably safe but more difficult and less flexible way

The setup is as follows: Two passwords exist. One is the normal password, the one that your normal installation has. The other is the master password (not a duress password in this case), which could provide deeper access into the system. This second password is set up using the pam\_duress module, and is connected with a script. The user can utilize the first password to normally use his computer and the second one to perform a hidden action (like unlocking a hidden portion of his disk). Passwords and secret information can be securely stored into the script used with the module since it is encrypted using the master password.

#### Security

First of all, the master password has the same level of security as any other password method, since it is salted and hashed when stored. It can safely be claimed then that the master password is just as safe as the normal password that the Linux installation has. Therefore, the master password cannot be exploited to gain access to the machine, since it's extremely difficult (impossible at this time in a reasonable amount of time) to crack. Since the hash function (in this case PBKDF2-SHA256) is provably safe, this module is by extension also safe. In addition, the contents of the script connected with the master password are also safe (so a secret code can be hard-coded in it), since it is encrypted (AES-256 CBC) using the master password.

#### Plausible deniability

Plausible deniability describes the ability of the user to deny the existence of an element, in this case, the use of a master password. While the mere existence of the installation of this module can be enough to deduce that the user is using it, it is also possible that another user is using the machine. Using the script `decoyscripts.sh`, a user can add decoy scripts that cannot be verified as legitimate or not. The hash function (PBKDF2-SHA256), as well as the encryption routine (AES-256 CBC) provably produce an output that is indistinguishable from random. Thus, the random output that `decoyscripts.sh` produces (in fact, the script is the AES encryption of a null file of a certain size and the username and password are chosen at random), is indistinguishable from a legitimate one.

### The unsafe but easy and flexible way

This setup also involves two password. Again, one is the normal password, though this time, this is the password that the user is trying to hide. The other password is the duress password, which will execute a panic script. The panic script can erase the user's data, send an alert signal to some authority, and whatever else the user would need in a panic situation. Obviously this setup does not provide deniability, but it does equally provide security. As in the safe way, this password cannot be cracked and cannot be exploited to gain access to the user's account. However, an adversary having full access to the user's machine, can check whether the password that the user provided to him is not legitimate (since using it he can decrypt the panic script and detect whether it is malicious or not). If, however, the user himself types the password, this installation is equally safe, since his actions can only be verified only after the script is executed (when it's too late for the adversary to accomplish his goal).


## Configuration

### common-auth
In order to use this module, you need to add it in one of the files in /etc/pam.d/ (for example in common-auth). You need to be careful on how you will add it so that it works properly. It is recommended that you put it in the primary block, right after the normal authentication module. It catches the last given password so in case the first module returns an authentication error, the authentication token goes right into the pam\_duress module.
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
auth	[success=3 default=ignore]      pam_unix.so nullok_secure
auth	[success=2 default=ignore]      pam_winbind.so krb5_auth krb5_ccache_type=FILE cached_login try_first_pass
auth    [success=1 default=ignore]      pam_duress.so allow

```

So I changed these values so that if the first two modules succeed, the duress module is not called, but if those two fail, the duress module is called, and if it succeeds it skips the next line and allows authentication.

If you want to provide authentication when the duress password is entered, make sure the argument after the duress module is `allow`. Otherwise, use `disallow`.

ATTENTION! If you allow authentication using the duress password, you should find a way to hide the fact that this was a duress password, because using it someone may be able to elevate to root permissions and, even if you change the permissions of `/usr/share/duress/hashes`, still be able to find whether you provided a duress password. A way to fix this is to delete (or alter) in your script your `hashes` file. Of course you'll need to rebuild it each time, but given that you'll be in a state of duress, it would be a good idea.

### Adding a user-password combination

Each user can have as many duress passwords as he/she wants, and each one with a different script to be run on login. Each user/password combination is concatenated (after the username is hashed) and the PBKDF2-SHA256 hash of this user-password concatenation is stored in `/usr/share/duress/hashes`. The structure of this file is a hash in hexadecimal format per line. You add a user-password combination, along with a script using the `adduser` command by executing `sudo ./adduser username password path` where you replace `username` with your username, `password` with your password and `path` with the path to your script. For example if your username is `foo`, your password is `bar` and your script is `./script.sh` you should type `sudo ./adduser foo bar script.sh`.

### Deleting a user-password combination

To delete a user-password that you created with `adduser`, use the `deluser.sh` script. Specifically, `sudo ./deluser.sh username password` deletes the user-password combination from `/usr/share/duress/hashes` as well as the associated script from `/usr/share/duress/scripts/`. For example, if your username is `foo` and your password is `bar`, you should type `sudo ./deluser.sh foo bar`.

### Creating decoy user-password combinations

In order to achieve a level of plausible deniability, the user should use this script to create decoy user-password combinations along with scripts, so that nobody can verify that they have actually used the duress module. This is implemented in the `decoyscripts.sh` script, which is used as `sudo ./decoyscripts.sh number` where `number` is the desired number of decoy user-password combinations.

## Compilation

As usual:
```bash
make
sudo make install
make clean
```

## TL;DR

* Download source and get into its directory.

* Install pam\_duress:
```bash
make
sudo make install
make clean
```

* Edit /etc/pam.d/common-auth and add `auth sufficient pam_duress.so` at the end of the primary block. Make sure that on failure of the above protocols it is run, and on success it is not.

* Set your username, password and duress script:
```bash
sudo ./adduser username password /path/to/script
```
(Replace `username` with your username, `password` with your password and `/path/to/script` with the absolute or relative path to your script.)
