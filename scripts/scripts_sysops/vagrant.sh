#!/bin/bash

echo "Timestamp the box..."
date '+%F %T' > /etc/issue.vagrant

echo "Create the vagrant user and group if it doesn't exit..."
if [[ ! -d "/home/vagrant" ]]; then
    /usr/sbin/groupadd vagrant
    /usr/sbin/useradd -g vagrant -p $(perl -e'print crypt("vagrant", "vagrant")') -m -s /bin/bash vagrant
fi

echo "Add the vagrant user to the sudo group..."
usermod -a -G sudo vagrant

# Set password-less sudo for the vagrant user (Vagrant needs it)...
echo '%vagrant ALL=NOPASSWD:ALL' > /etc/sudoers.d/vagrant
chmod 0440 /etc/sudoers.d/vagrant
