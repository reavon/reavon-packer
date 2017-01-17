#!/bin/bash

Filesystem=$(awk '!/selinux/&&/xfs|ext/' /etc/mtab)

for i in $FileSystem
do
    echo $i
    number=$(df -B 512 $i | awk -F" " '{ print $3 }' | grep -v Used)
    echo $number
    percent=$(echo "scale=0; $number * 98 / 100" | bc)
    echo $percent
    dd count=$(echo $percent) if=/dev/zero of=$(echo $i)/zf
    /bin/sync
    sleep 15
    rm -f ${i}/zf
done

VolumeGroup=$(/usr/sbin/vgdisplay | grep Name | awk -F" " '{ print $3 }')

for j in $VolumeGroup
do
    echo $j
    /usr/sbin/lvcreate -l $(/usr/sbin/vgdisplay $j | grep Free | awk -F" " '{ print $5 }') -n zero $j
    if [ -a /dev/${j}/zero ]; then
            cat /dev/zero > /dev/${j}/zero
            /bin/sync
            sleep 15
            /usr/sbin/lvremove -f /dev/${j}/zero
    fi
done

# Make sure we wait until all the data is written to disk, otherwise
# Packer might quit too early before the large files are deleted
exit
