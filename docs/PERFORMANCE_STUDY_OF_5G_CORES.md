# Performance study of Open Source 5G Core networks

This gives a tutorial on the performance study of open source 5g networks. We use this 5G traffic generator to generate and perform registration procedures for multiple UEs. We will use [bcc tools](https://github.com/iovisor/bcc) and [bpftrace tools](https://github.com/iovisor/bpftrace) to do a granular performance analysis of the underlying resources whilst load testing the 5G core networks.

We look at the following 5G core networks
1. [Open Air Interface - 5G CORE NETWORK](https://openairinterface.org/oai-5g-core-network-project/)
2. [free5gc](https://www.free5gc.org/)
3. [Open5gs](https://open5gs.org/)

In the study we configure the 5G core networks to use a single and the same ciphering and encryption NIA1 and NEA1.

We set up the environment on openstack. In our case we install openstack locally on our workstation. We then set up the traffic generator and the core networks on VM on openstack and configure for communication. To make it easier to set up and run the performance analysis we make use of [Ansible](https://www.ansible.com/). Ansible helps in making the study easy to reproduce and the results easier to collect. We author the ansible roles and plays necessary for this study on [this](https://github.com/tariromukute/opengilan) repository.

This study will:
1. [Install and set up openstack on a workstation](#install-and-set-up-openstack-on-a-workstation)
2. [Set up and install the traffic generator on a VM on openstack](#set-up-and-install-the-traffic-generator-on-a-vm-on-openstack)
3. [Detail how to set up performance analysis tools](#how-to-set-up-performance-analysis-tools)
3. [Install, set up OAI CN and collect performance analysis logs](#install-set-up-oai-cn-and-collect-performance-analysis-logs)
4. [Install, set up free5gc and collect performance analysis logs](#install-set-up-free5gc-and-collect-performance-analysis-logs)
5. [Install, set up Open5gs and collect performance analysis logs](#install-set-up-open5gs-and-collect-performance-analysis-logs)

## Install and set up openstack on a workstation

There are two options for setting up the local cloud (testbed), [using Microstack](#using-microstack) and [using Devstack](#using-devstack). Microstack worked fine for a start but there we couple of issues I had to workaround. You can see this under the [Microstack Gotchas](#microstack-gotchas) section. One of the issues ended up reoccuring and could resolve it so had to switch to Devstack. It is possible that one might not face the issue on their environment. Based on this we recommend using Devstack for replicaing the study. Aside from the issues encountered with Microstack, with Devstack you can use the latest stable version of openstack `zed` where as Microstack will install `ussuri` (at the time of writing).

**Installing devstack**

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

**Configure credentials**

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

**Install Devstack**

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

openstack port create --network ${PRIVATE_NET_ID} --fixed-ip subnet=my-subnet test-1

openstack port create --network ${PRIVATE_NET_ID} --fixed-ip subnet=opencn_tg-vxlan test_0

# Create server (core network)
openstack server create --flavor m2.medium \
    --image 20.04 \
    --key-name  stack \
    --nic port-id=$(openstack port show test_0 -c id -f value) \
    --nic port-id=$(openstack port show test_1 -c id -f value) \
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

```bash
# Set up for XDP_REDIRECT
 sudo ethtool -L enp1s0 combined $(nproc)

```
**Uninstall Devstack**

```bash
# Clean
./clean.sh

# Remove
./unstack.sh
```

#### Microstack Gotchas

> Encountered a recurring error `Permission denied (publickey)`. Initially disabling and re-enabling microstack worked. See thread [here](https://serverfault.com/questions/1089057/openstack-ubuntuvm-ssh-public-key-permission-denied-on-first-boot). However this doesn't seem to work everytime. It ended up disrupting the study. The details of the issue are described [here](https://askubuntu.com/questions/1321968/ubuntu-server-20-04-2-lts-hangs-after-bootup-cloud-init-1781-yyyy-mm-dd-h)

> Microstack during installation binds to the IP address of the primary interface. When restarting the workstation sometimes microstack would become unavailable. You are able to get the login page but ultimately you can't see the dashboard. Running `sudo snap logs microstack` showed one of the error to be `Can't connect to MySQL server on '192.168.100.11' ([Errno 113] No route to host`. In general all the error logs had to do with connection. Turns out that microstack hardcoded the external ip address during installation. On an laptop environment, a laptop using wifi and dynamic ip allocation, the external ip address changes on reboot. This is bug is also discussed on [here](https://bugs.launchpad.net/microstack/+bug/1942741). The resolution was to set the wifi interface to a static ip address. I after this I had to reboot my machine, disable then enable microstack. Maybe one of those steps might not be necessary. These steps resolved my issue.

## How to set up performance analysis tools

To set up the tools you will need to create a VM to run them on. In this study you will need to set up the tools on the VMs for the core networks. The section is to be referenced after setting up the VMs.

### Set up bcc tools to collect system performance results

We will install bcc from source because we want to print the results in json format for easier visualisation. We raised a PR for this to be part of the bcc project [here](), but it's not yet merged, still under consideration. The source is a fork repo.

To install we are going to use an ansible role. One downside of the ansisble ad-hoc cli commands that we are using is they don't have access to the ansible_facts which the role. A workaround is to cache them and then use them in the next command. This is recommanded on a comment on [this](https://stackoverflow.com/questions/38350674/ansible-can-i-execute-role-from-command-line#) thread. 

```bash
# Cache the ansible_facts
ANSIBLE_CACHE_PLUGIN=jsonfile ANSIBLE_CACHE_PLUGIN_CONNECTION=/tmp/ansible-cache \
ansible all -i '172.24.4.3,' -u ubuntu -m setup

# Run the ansible role for OAI. Replace 172.24.4.3 with the IP of the OAI VM
ANSIBLE_CACHE_PLUGIN=jsonfile ANSIBLE_CACHE_PLUGIN_CONNECTION=/tmp/ansible-cache \
ansible all -i '172.24.4.3,' -u ubuntu -m include_role --args "name=olan_bcc" -e user=ubuntu
```

### Set up bpftrace to collect system performance results

We will build from source because the version of bpftrace on ubuntu packages doesn't allow printing of output in json format. Json output format is important for graphing the results.

We will use an ansible role for this.

### Copy bash script to collect results partitioned by variables

```bash
# Copy tools file
ansible all -i '172.24.4.3,' -u ubuntu -m ansible.builtin.copy -a "src=files/tools dest=/home/ubuntu"

# Make main script executable
ansible all -i '172.24.4.3,' -u ubuntu -m ansible.builtin.file -a "dest=/home/ubuntu/tools/main.sh mode=a+x"
```

## Set up and install the traffic generator on a VM on openstack

Start by creating a VM for the traffic generator as detailed in the [earlier section](#install-and-set-up-openstack-on-a-workstation). Now ssh into the VM and run the commands below.

```bash
sudo apt update

# Download the traffic generator
git clone https://github.com/tariromukute/core-tg.git

# Install dependecies
cd core-tg/
git submodule init
git submodule update

sudo apt-get install python3-dev
sudo apt-get install build-essential
sudo apt install python3.8-venv

# Create virtual environment for the app and install requirements
python3 -m venv .venv
source .venv/bin/activate

pip install pycrate
pip install pysctp
pip install cryptography
pip install pyyaml

# Set up the CryptoMobile module
cd CryptoMobile && python3 setup.py install
```

## Install, set up OAI CN and collect performance analysis logs

We can set up OAI by running the steps from the [GitLab repository](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-fed/-/blob/master/docs/DEPLOY_HOME.md). However, created an ansible role that can set up OAI. The ansible role should make it easier. If you prefere you can create the VM and install following the instructions from OAI repository.

Create a VM for OAI as describe under in [previous section](#install-and-set-up-openstack-on-a-workstation)

**Set up using an ansible role**

To set up OAI you can follow the instruction on the offical site. Created an ansible role that can set up OAI. The role does the following.
1. Install dependencies for OAI
2. Pulls and runs the OAI docker images
3. Sets up the networking rules to allow traffic forward on VM to the docker containers
4. Add an sql dump to initialise OAI with UEs for testing 208950000000031 - 208950000100031
5. Copies docker-compose file to run OAI on network 48.0.0.0/16.

```bash
# Firstly install ansible

# Run the ansible role for OAI. Replace 172.24.4.3 with the IP of the OAI VM
ansible all -i '172.24.4.3,' -u ubuntu -m include_role --args "name=olan_oai_cn5g" -e docker_username=<username> -e docker_password=<password> -e user=ubuntu
```

**Set up connection between OAI and 5G traffic generator**

On the Host

```bash
router="router1"
oai_ip="10.0.0.47" # from private subnet
oai_port_id="d97cbf58-a17f-492f-a568-6a01ab4e769d" # run 'openstack port list' and check for the port with ip above

# (1) Add a static route to the Router (with 48.0.0.0/16 in our case - the subnet of the OAI docker container in docker compose)
openstack router set ${router} \
    --route destination=48.0.0.0/16,gateway=${oai_ip}
    
# (2) Add Allowed Address Pairs under the instance interface (48.0.0.0/16 in our case)
openstack port set ${oai_port_id} --allowed-address ip-address=48.0.0.0/16
```

On the OAI VM

```bash
sudo sysctl net.ipv4.conf.all.forwarding=1
sudo iptables -P FORWARD ACCEPT
# Enable the proxy arp for ARP request from the querying external host
sysctl -w net.ipv4.conf.all.proxy_arp=1
```

On the traffic generator VM

```bash
# Set route for the OAI traffic. Substitute 10.0.0.89 with the private IP of the traffic generator
ip route add 48.0.0.0/16 via 10.0.0.89
```

**Start the 5G Core**

```bash
cd oai-cn5g-fed/docker-compose/
docker compose -f docker-compose-basic-nrf.yaml up -d

# Confirm all services are healthy. This may take time
docker ps
```

**Start the 5G core traffic generator**

```bash
cd ~/core-tg/
source .venv/bin/activate

# -t : duration of the traffic generator should run for>
# -n : number of UE to register, starting with the UE is IMSI in the ai-cn5g-ue.yaml
# -f : file to write logs to
# -u : config file for UE
# -g : config file for GNB
python3 src/app.py -t 20 -i 0 -n 1 -f /tmp/core-tg -u src/config/oai-cn5g-ue.yaml -g src/config/oai-cn5g-gnb.yaml
```
Based on the logs you can check if the traffic is flowing and there has been registration.
1. Check the OAI logs for each service `docker compose -f docker-compose-basic-nrf-1.yaml logs --tail 100`
2. Check the logs from the traffic generator `cat /tmp/core-tg/core-tg.log`


### Collect performance analysis results

First you need to install the tools for performance analysis as explaned in [this section](#how-to-set-up-performance-analysis-tools). We will make use of an ansible play on [this repo](https://github.com/tariromukute/opengilan/blob/main/ansible/plays/oai.yml) to collect the results. The play will:
1. Restart the core network
2. Start the specified performance analysis tool
3. Start the traffic generator
4. After the specified duration pull the performance results and traffic generator logs
5. Save the logs in the `.results folder`

Before running you will need to create an inventory file `inventory.ini` for the VMs. Paste the contents below in the file. client1 should be the ip of the traffic generator and server1 should be the ip of the core network.

```
[az_trex]
client1 ansible_host=172.24.4.49 ansible_user=ubuntu ansible_ssh_private_key_file=/opt/stack/.ssh/id_rsa
[az_sut]
server1 ansible_host=172.24.4.3 ansible_user=ubuntu ansible_ssh_private_key_file=/opt/stack/.ssh/id_rsa
```

Afterwards run the play to collect logs.

```bash
# Create results folder
mkdir .results

# Start Core Network and Traffic generator
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/oai.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -m -j", tool: syscount, ues: 0 }'
```

Visualise the results by using [this notebook](https://github.com/tariromukute/opengilan/blob/main/notebooks/Report%20-%205G%20Core%20Networks%20copy.ipynb) 

#### OAI Gotchas

> Tried running the OAI on Ubuntu 20.04 VM on microstack. The oai-amf container failed with socket error. Realised that this was due to the SCTP module missing on the kernel `lsmod | grep sctp`. I tried locating the module with `modinfo sctp` but it was not found. I ran `sudo apt install linux-generic` to get the extra modules. I could now find the module and tried loading with `insmod <path_to_module>`. This failed. Turns out I was using the `focal-server-cloudimg-amd64-disk-kvm.img` as recommended or pointed to on one of the Microstack blogs. I switched to creating a VM from image `focal-server-cloudimg-amd64.img`. This also didn't have the SCTP module load but I could find it on the system. I loaded the module `modprobe sctp` and then ran the OAI and this time it worked. I assume this would be the case for all the core networks. Used the same image for the rest of the core networks.

> The OAI CN generates a lot of debug logs. Although the documentation (at the time of writing) states that the network functions produce info level logs see [docs](https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-fed/-/blob/master/docs/DEBUG_5G_CORE.md#1-building-images-in-debug-mode). The docker containers from oaisoftwarealliance tags v1.4.0 and v1.5.0 produce debug logs. When doing load testing this affects the performance of the core network.

## Install, set up free5gc and collect performance analysis logs

Start by creating a VM for OAI as describe under in [previous section](#install-and-set-up-openstack-on-a-workstation)

We can set up freegc by following the instruction from the [free5gc repository](https://github.com/free5gc/free5gc/wiki/Installation). We created an ansible role that can set up free5gc. The ansible role should make it easier. If you prefere you can create the VM and install following the instructions from free5gc repository.

**Install Free5gc**

```bash
# Run the ansible role for free5gc. Replace 172.24.4.223 with the IP of the free5gc VM

# Cache the ansible_facts
ANSIBLE_CACHE_PLUGIN=jsonfile ANSIBLE_CACHE_PLUGIN_CONNECTION=/tmp/ansible-cache \
ansible all -i '172.24.4.223,' -u ubuntu -m setup

ANSIBLE_CACHE_PLUGIN=jsonfile ANSIBLE_CACHE_PLUGIN_CONNECTION=/tmp/ansible-cache \
ansible all -i '172.24.4.223,' -u ubuntu -m include_role --args "name=olan_free5gc" -e user=ubuntu
```

**Start the 5G Core**

```bash
systemctl restart free5gc
# the anisble role creates a unit service for free5gc. If you set up from the repo, run below commands
cd ~/free5gc
./run.sh
```

**Start the 5G core traffic generator**

You will need to update the ip address in the files `src/config/free5gc-ue.yaml` and  `src/config/free5gc-gnb.yaml` on the core network VM.

```bash
cd ~/core-tg/
source .venv/bin/activate

# -t : duration of the traffic generator should run for>
# -n : number of UE to register, starting with the UE is IMSI in the ai-cn5g-ue.yaml
# -f : file to write logs to
# -u : config file for UE
# -g : config file for GNB
python3 src/app.py -t 20 -i 0 -n 1 -f /tmp/core-tg -u src/config/free5gc-ue.yaml -g src/config/free5gc-gnb.yaml
```
Based on the logs you can check if the traffic is flowing and there has been registration.
1. Check the OAI logs for each service `journalctl -u free5gc -n 200`
2. Check the logs from the traffic generator `cat /tmp/core-tg/core-tg.log`

**Collect performance analysis results**

To setup for collection the tools follow instructions [here](#collect-performance-analysis-results), to start the collection run the commands below. Notice that we use a different play from the same repository [here](https://github.com/tariromukute/opengilan/blob/main/ansible/plays/free5gc.yml)

```bash
# Create results folder
mkdir .results

# Start Core Network and Traffic generator
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/free5gc.yml \
    -e user=ubuntu -e duration=20 -e aduration=35 -e interval=0 \
    -e tool=syscount -e ues=50
```

Visualise the results by using [this notebook](https://github.com/tariromukute/opengilan/blob/main/notebooks/Report%20-%205G%20Core%20Networks%20copy.ipynb) 

## Install, set up Open5gs and collect performance analysis logs

Start by creating a VM for OAI as describe under in [previous section](#install-and-set-up-openstack-on-a-workstation)

We can set up freegc by following the instruction from the [open5gs installation guide](https://open5gs.org/open5gs/docs/guide/01-quickstart/). We created an ansible role that can set up open5gs. The ansible role should make it easier. If you prefere you can create the VM and install following the instructions from open5gs installation guide.

**Install Open5gs**

```bash
# Firstly install ansible

# Replace 172.24.4.163 with the IP of the Open5gs VM
# Cache the ansible_facts
ANSIBLE_CACHE_PLUGIN=jsonfile ANSIBLE_CACHE_PLUGIN_CONNECTION=/tmp/ansible-cache \
ansible all -i '172.24.4.39,' -u ubuntu -m setup

ANSIBLE_CACHE_PLUGIN=jsonfile ANSIBLE_CACHE_PLUGIN_CONNECTION=/tmp/ansible-cache \
ansible all -i '172.24.4.39,' -u ubuntu -m include_role --args "name=olan_open5gs" -e user=ubuntu
```

**Start the 5G Core**

```bash
# systemctl restart open5gs-* had issues because systemctl restart open5gs-dbctl was missing
systemctl restart open5gs-amfd open5gs-upfd open5gs-scpd open5gs-nrfd open5gs-mmed open5gs-udrd open5gs-sgwud open5gs-sgwcd open5gs-ausfd open5gs-pcrfd open5gs-pcfd open5gs-bsfd open5gs-hssd open5gs-nssfd open5gs-udmd open5gs-smfd
```

**Start the 5G core traffic generator**

You will need to update the ip address in the files `src/config/open5gs-ue.yaml` and  `src/config/open5gs-gnb.yaml` on the core network VM.

```bash
cd ~/core-tg/
source .venv/bin/activate

# -t : duration of the traffic generator should run for>
# -n : number of UE to register, starting with the UE is IMSI in the ai-cn5g-ue.yaml
# -f : file to write logs to
# -u : config file for UE
# -g : config file for GNB
python3 src/app.py -t 20 -i 0 -n 1 -f /tmp/core-tg -u src/config/open5gs-ue.yaml -g src/config/open5gs-gnb.yaml
```
Based on the logs you can check if the traffic is flowing and there has been registration.
1. Check the OAI logs for each service `journalctl -u open5gs-* -n 200`
2. Check the logs from the traffic generator `cat /tmp/core-tg/core-tg.log`

**Collect performance analysis results**

To setup for collection the tools follow instructions [here](#collect-performance-analysis-results), to start the collection run the commands below. Notice that we use a different play from the same repository [here](https://github.com/tariromukute/opengilan/blob/main/ansible/plays/open5gs.yml)

```bash
# Create results folder
mkdir .results

# Start Core Network and Traffic generator
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -m -j", tool: syscount, ues: 0 }'
```
