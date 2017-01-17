#!/bin/bash

## Let's figure out where the install directory is
  ## Determine the absolute path to the install_virtualbox.sh script
abspath="$(cd ${0%/*} 2>/dev/null; echo $PWD/${0##*/})"
  ## Now get the directory name that contains the install_virtualbox.sh script
export install_dir=`dirname $abspath`

lsb_distributor=$(lsb_release -i | awk '{print $3}' | tr '[:upper:]' '[:lower:]')
lsb_release=$(lsb_release -a | grep Release | awk '{print $2}' | cut -d \. -f 1)

download_url='http://download.virtualbox.org/virtualbox'

pushd () {
    command pushd "$@" > /dev/null
}

popd () {
    command popd "$@" > /dev/null
}

if [ $lsb_distributor != fedora ]; then
    echo "This script is for Fedora only!"
    exit 1
fi

virtualbox_version="$(wget --quiet --output-document=- ${download_url}/LATEST.TXT)"

files="
SHA256SUMS
UserManual.pdf
Oracle_VM_VirtualBox_Extension_Pack-${virtualbox_version}.vbox-extpack
VBoxGuestAdditions_${virtualbox_version}.iso
"

if [ ! -d ${install_dir}/virtualbox ]; then
    mkdir -p ${install_dir}/virtualbox
fi

pushd ${install_dir}/virtualbox

for file in ${files}; do
      echo "Downloading $file"
      wget --quiet --recursive --timestamping --no-directories --continue \
          ${download_url}/${virtualbox_version}/${file}
done

mv SHA256SUMS SHA256SUMS-VBoxGuestAdditions_${virtualbox_version}.txt
mv UserManual.pdf UserManual-${virtualbox_version}.pdf

echo "Downloading Virtualbox ${virtualbox_version} for Fedora ${lsb_release}"
wget --recursive --quiet --timestamping --no-directories --continue \
        --level=1 --no-parent --accept "*${lsb_distributor}${lsb_release}*.x86_64.rpm" \
        ${download_url}/${virtualbox_version}

rm robots.txt

popd

virtualbox=$(ls ${install_dir}/virtualbox/VirtualBox*.rpm)

if [ $(rpm -qa kernel |sort -V |tail -n 1) == kernel-$(uname -r) ]; then
    echo ""
    echo ""
    echo "Virtualbox $virtualbox_version has been downloaded. To install, issue the following sudo commands:"
    echo "sudo dnf install binutils gcc make patch libgomp glibc-headers glibc-devel kernel-headers kernel-devel dkms ${install_dir}/${virtualbox}"
    echo "sudo gpasswd -a ${USER} vboxusers"
    echo ""
else
    echo ""
    echo "Virtualbox $virtualbox_version has been downloaded"
    echo ""
    echo "You are not running the latest installed kernel. Reboot and issue the following sudo commands:"
    echo "sudo dnf install binutils gcc make patch libgomp glibc-headers glibc-devel kernel-headers kernel-devel dkms ${install_dir}/${virtualbox}"
    echo "sudo gpasswd -a ${USER} vboxusers"
    echo ""
fi
