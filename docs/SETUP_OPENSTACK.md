# Deploy and setup Openstack

There are two options for setting up the local cloud (testbed), [using Microstack](#using-microstack) and [using Devstack](#using-devstack). Microstack worked fine for a start but there we couple of issues I had to workaround. You can see this under the [Microstack Gotchas](#microstack-gotchas) section. One of the issues ended up reoccuring and could resolve it so had to switch to Devstack. It is possible that one might not face the issue on their environment. Based on this we recommend using Devstack for replicaing the study. Aside from the issues encountered with Microstack, with Devstack you can use the latest stable version of openstack `zed` where as Microstack will install `ussuri` (at the time of writing).

## Setup for devstack installation

```bash
# Add user
sudo useradd -s /bin/bash -d /opt/stack -m stack

# 
sudo chmod +x /opt/stack

#
echo "stack ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/stack
sudo -u stack -i

git clone https://opendev.org/openstack/devstack
cd devstack

# Switch to openstack version of choice
git checkout stable/zed
```

## Configure credentials

Need to create credentials config file (`local.conf`) before installing the stack inside folder devstack. See example below.

> Note: putting HOST_IP=0.0.0.0 will ensure that openstack doesn't bind to you network interface IP address. This is helpful when you are on WIFI and you IP is dynamically allocated or changes depending on the network

```
[[local|localrc]]
ADMIN_PASSWORD=secret
DATABASE_PASSWORD=$ADMIN_PASSWORD
RABBIT_PASSWORD=$ADMIN_PASSWORD
SERVICE_PASSWORD=$ADMIN_PASSWORD
HOST_IP=0.0.0.0
```

> Note: When installing on ubuntu 22.04 got an error of repository/PPA does not have a Release file for some of the packages. Implemented the workaround from [here](https://github.com/unetbootin/unetbootin/issues/305), which is to use PPA release files for ubuntu 20.04.

```bash
# Change PPA configuration
sudo sed -i 's/jammy/focal/g' /etc/apt/sources.list.d/gezakovacs-ubuntu-ppa-jammy.list
sudo sed -i 's/jammy/focal/g' /etc/apt/sources.list.d/system76-ubuntu-pop-jammy.list
```

## Install Devstack

```bash
./stack.sh
```

When you restart the service you might have issues with devstack. In my case I had error with openvswitch. Resolved it by following steps on [this](https://stackoverflow.com/questions/68001501/error-opt-stack-devstack-lib-neutron-plugins-ovn-agent174-socket) StackOverflow thread.

**Using openstack CLI**

In order to use the CLI you will need to set the env variables.

```bash
sudo su - stack
cd devstack

# username: admin, project: demo
source openrc admin demo
```

## Setup a virtual machine

**Download and create Ubuntu image**

```bash
cd ~/
mkdir images

# Download image
wget https://cloud-images.ubuntu.com/focal/current/focal-server-cloudimg-amd64.img -o images/focal-server-cloudimg-amd64.img

# Create Ubuntu image
openstack image create \
    --container-format bare \
    --disk-format qcow2 \
    --min-disk 8 --min-ram 512 \
    --file images/focal-server-cloudimg-amd64.img \
    --public 20.04

# Confirm image created
openstack image list

# Create flavor we are using for testing
openstack flavor create --public m2.medium --id auto \
    --ram 4096 --disk 50 --vcpus 2 --rxtx-factor 1
```

Create ssh keys to attach to servers

```bash
# Generate keys
ssh-keygen -t rsa -b 4096

# Add key to openstack
openstack keypair create --public-key /opt/stack/.ssh/id_rsa.pub stack

# Confirm key was created
openstack keypair list
```

**Setup the rules to enable networking of the VMs with the internet**

```bash
# On HOST machine: Enable traffic to be correctly routed out of the VMs on Devstack
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/conf/<interface>/proxy_arp
iptables -t nat -A POSTROUTING -o <interface> -j MASQUERADE

# Devstack does not wire up the public network by default so we must do that before connecting to this floating IP address.
sudo ip link set br-ex up
sudo ip route add 172.24.4.0/24 dev br-ex
sudo ip addr add 172.24.4.1/24 dev br-ex

# By default, DevStack does not allow users to access VMs, to enable that, we will need to add a rule. We will allow both ICMP and SSH.
# If you get error of more than one security group with name default, use the security group id instead
openstack security group rule create --ingress --ethertype IPv4 --dst-port 22 --protocol tcp default
openstack security group rule create --ingress --ethertype IPv4 --protocol ICMP default
openstack security group rule list

# Enable DHCP for the VMs
openstack subnet set --dhcp private-subnet
openstack subnet set --dns-nameserver 8.8.8.8 private-subnet
```

**Create servers for testing (Documented instructions from [here](https://docs.openstack.org/networking-ovn/latest/contributor/testing.html))**

```bash
# Get net id for private network
PRIVATE_NET_ID=$(openstack network show private -c id -f value)

# Create server (core network)
openstack server create --flavor m2.medium \
    --image 20.04 \
    --key-name  stack \
    --nic net-id=${PRIVATE_NET_ID} \
    <server-name>

openstack floating ip create --project demo --subnet public-subnet public

openstack server add floating ip <server-name> <float-ip>
# Confirm
openstack server list

# Test ping
ping -c 4 <ip-address>

# Confirm SSH into instance
ssh ubuntu@<float-ip>
```

## Uninstall Devstack

```bash
# Clean
./clean.sh

# Remove
./unstack.sh
```

#### Microstack Gotchas

> Encountered a recurring error `Permission denied (publickey)`. Initially disabling and re-enabling microstack worked. See thread [here](https://serverfault.com/questions/1089057/openstack-ubuntuvm-ssh-public-key-permission-denied-on-first-boot). However this doesn't seem to work everytime. It ended up disrupting the study. The details of the issue are described [here](https://askubuntu.com/questions/1321968/ubuntu-server-20-04-2-lts-hangs-after-bootup-cloud-init-1781-yyyy-mm-dd-h)

> Microstack during installation binds to the IP address of the primary interface. When restarting the workstation sometimes microstack would become unavailable. You are able to get the login page but ultimately you can't see the dashboard. Running `sudo snap logs microstack` showed one of the error to be `Can't connect to MySQL server on '192.168.100.11' ([Errno 113] No route to host`. In general all the error logs had to do with connection. Turns out that microstack hardcoded the external ip address during installation. On an laptop environment, a laptop using wifi and dynamic ip allocation, the external ip address changes on reboot. This is bug is also discussed on [here](https://bugs.launchpad.net/microstack/+bug/1942741). The resolution was to set the wifi interface to a static ip address. I after this I had to reboot my machine, disable then enable microstack. Maybe one of those steps might not be necessary. These steps resolved my issue.
