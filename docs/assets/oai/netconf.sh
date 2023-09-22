#!/bin/bash

# Define array of IP addresses and hostnames
ip_addrs=(
    "127.0.0.1 mysql"
	"127.0.0.130 oai-nrf"
	"127.0.0.132 oai-amf"
	"127.0.0.133 oai-smf"
	"127.0.0.134 oai-spgwu"
	"127.0.0.135 oai-ext-dn"
	"127.0.0.136 oai-udr"
	"127.0.0.137 oai-udm"
	"127.0.0.138 oai-ausf"
)

# Loop through each IP address and configure loopback interface and hostnames
for ip in "${ip_addrs[@]}"; do
	ip_addr=$(echo $ip | cut -d" " -f1)
	hostname=$(echo $ip | cut -d" " -f2)

	# Add interface alias
	number=$(echo $ip_addr | awk -F. '{print $4}')
	ifconfig lo:$number $ip_addr netmask 255.0.0.0 up
	
	# Check if hostname already exist
	if grep -q "$hostname" /etc/hosts; then
		echo "Hostname '$hostname' already exists in /etc/hosts"
	else
		echo "$ip_addr $hostname" >> /etc/hosts
	fi
done
