#!/bin/bash

function download()
{
    sudo apt-get update;
    export DEBIAN_FRONTEND=noninteractive;
    sudo ln -fs /usr/share/zoneinfo/Europe/Rome /etc/localtime;
    sudo apt-get install tzdata -y;
    while read line; do
      echo "************************** Installing $line ***********************"
      sudo apt-get install $line -y;
    done < packages.txt

}

echo "Starting installation of the FirmAFL packages......this could take some time."
sudo apt update;
export DEBIAN_FRONTEND=noninteractive
echo "Europe/Rome" > /etc/timezone
ln -fs /usr/share/zoneinfo/Europe/Rome /etc/localtime
apt-get install -y tzdata
dpkg-reconfigure -f noninteractive tzdata
sudo apt install -y software-properties-common;
sudo add-apt-repository -y ppa:deadsnakes/ppa;
sudo apt-get install -y python3.7 cmake git cmake libcurl4-openssl-dev;
echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo debconf-set-selections
sudo apt-get install -y wireshark
git clone https://github.com/Cyan4973/xxHash
cd xxHash
cmake build/cmake -DBUILD_SHARED_LIBS=OFF -DBUILD_STATIC_LIBS=ON
cmake --build .
cmake --build . --target install
cd /STAFF
rm -r xxHash
sudo apt install -y python3.7-distutils;
sudo python3 -m pip install scapy scipy matplotlib_venn venn colorama docker angr;
download
sudo python3 -m pip config set global.break-system-packages true
dpkg -i liburing1_0.7-3~bpo10+1_amd64.deb
dpkg -i liburing-dev_0.7-3~bpo10+1_amd64.deb
echo -e "Starting installation of FirmAE";
cd FirmAE
./install.sh
cd ..
# ./install_buildroot.sh
