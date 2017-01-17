#!/bin/bash

# Install the cloud init tools
yum --assumeyes install cloud-init cloud-utils cloud-utils-growpart python2-boto \
    perl-Switch perl-DateTime perl-LWP-Protocol-https zip unziplibguestfs-tools

# Make sure our stuff is set to start on boot
/bin/systemctl -q enable cloud-init cloud-init-local cloud-config cloud-final

# Tweak sshd to prevent DNS resolution (speed up logins)
sed -i -e '/^[# ]*UseDNS/{s/^[# ]*\([^ ]*\)[ ]*.*$/\1 no/;s/^#//}' /etc/ssh/sshd_config

# For instance access to metadata service, disable the default zeroconf route
if grep -q ^NOZEROCONF /etc/sysconfig/network; then
    sed -i 's/NOZEROCONF.*/NOZEROCONF=yes/g'
else
    echo "NOZEROCONF=yes" >> /etc/sysconfig/network
fi

# Copy (retains permissions) cloud.cfg that was uploaded with packer file provisioner
cp /tmp/cloud.cfg /etc/cloud/cloud.cfg
rm /tmp/cloud.cfg

cat > /root/.bashrc << 'BASHRC'
umask 022

set -o vi

if [ -f /bin/dircolors ]; then
    eval "`dircolors`"
fi

export LS_OPTIONS='--color=auto'

alias ls='ls $LS_OPTIONS'
alias ll='ls $LS_OPTIONS -l'
alias l='ls $LS_OPTIONS -lA'

export PS1='\e[32;1m\u\e[m\e[30m@\e[31;1m\h\e[m\e[30m:\e[36;1m\w\e[m\n% '
BASHRC

cat > /root/.inputrc << 'INPUTRC'
set completion-ignore-case on
set print-completions-horizontally off
set visible-stats on
set show-all-if-ambiguous on
set colored-stats on

set comment-begin #
set keymap vi

set editing-mode vi
Control-l: clear-screen
INPUTRC

