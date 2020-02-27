#!/bin/bash
echo"#################################################
## Debian 10 buster PAM_DURESS INST AND CONFIG ##
##             by: hellrezistor                ##
##                2020-02-25                   ##
#################################################"
sleep 3

echo "Lets Config a PANIC PASSWORD ;)"
sleep 2

sudo apt install -y git make build-essential libpam0g-dev libssl1.1 libssl-dev
git clone https://github.com/Lqp1/pam_duress
# apt install libcurl4-openssl-dev libpam-cracklib ## check if REALLY needed installed..

cd pam_duress
make
sudo make install
make clean

sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.bck
cat <<EOF> /etc/pam.d/common-auth
auth    [success=3 default=ignore]      pam_unix.so nullok_secure
auth    [success=2 default=ignore]      pam_duress.so disallow
auth    sufficient                      pam_duress.so
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
EOF

sudo ln -s /usr/lib/security /lib/security

read -p -s "WRITE a Panic Password to your user: $USER" PANICPSWD

if [ -z "$ScriptLoc" ]; then
 ScriptLoc="$PWD/pam_duress/examples/delete-all.sh"
else
 read -p " Your User: $USER
 PanicPswd: $PANICPSWD
 Script: $ScriptLoc
 
 Are you SURE?? .. <Enter> "
fi

sudo pam_duress_adduser $USER $PANICPSWD $ScriptLoc
read -p "$USER Panic Password Created with execution script: $ScriptLoc
Press <Enter> Key to FINISH"
}
