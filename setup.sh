#!/bin/bash

INSTALLATION_DIR=$(pwd)

# Check if the required packages are installed and install them if they are not
packages=(python3-dev python3-pip python3-bpfcc bpfcc-tools libbpf-dev linux-headers-$(uname -r) build-essential)
for package in "${packages[@]}"
do
    if ! dpkg -s "$package" >/dev/null 2>&1; then
        sudo apt-get -y install "$package"
    fi
done

if ! dpkg -s "clang-14" >/dev/null 2>&1; then
    sudo apt-get -y install clang-14
    sudo ln /usr/bin/clang-14 /usr/bin/clang
fi

# List of required packages
PACKAGES=(pycrate pysctp scapy cryptography pyyaml tabulate matplotlib)

# Loop through each package and check if it's installed
for package in "${PACKAGES[@]}"
do
    if ! sudo pip freeze | grep -i $package > /dev/null; then
        echo "$package is not installed. Installing..."
        sudo pip install $package
    else
        echo "$package is already installed."
    fi
done

# initialize your local configuration file with git submodule init and git submodule update 
git submodule init
git submodule update

# Build the a shared c library of file src/xdpgen/xdpgen.c using clang
clang -shared -o src/xdpgen/libxdpgen.so src/xdpgen/xdpgen.c -lbpf

# Create an ENV variable XDP_INCLUDE_PATH that points to src/xdpgen/
export APP_INCLUDE_PATH=$(pwd)

echo "The value of APP_INCLUDE_PATH is: $APP_INCLUDE_PATH"

# Install CryptoMobile
cd CryptoMobile && sudo python3 setup.py install

cd $INSTALLATION_DIR
