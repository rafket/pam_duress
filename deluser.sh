#!/bin/bash
if [[ $EUID -ne 0 ]]; then
    echo "This action must be run as root"
    exit 1
elif [ $# -ne 2 ]
    then
        echo -e "Usage: deluser.sh username password\n  Deletes a user-password-action combination from the database\n  username: The username of the account that the entry was created for\n  password: The password of the account of the user above";
else
    ln=1
    found=0
    while read line
        do
            salt=${line%:*}
            hsh=${line##*:}
            userhash=$(echo -n $1 | sha256sum | sed 's/  -//g')
            hash=$(echo -n $salt$userhash$2 | sha256sum | sed 's/  -//g')
            if [ $hsh == $hash ]
                then
                    found=1
                    break
            fi
            ((ln++))
    done < "/usr/share/duress/hashes"

    if [ $found == 1 ]
        then
            sed -i $ln'd' /usr/share/duress/hashes
            rm /usr/share/duress/actions/$hash
	else
	    echo "Not found";
    fi
fi
