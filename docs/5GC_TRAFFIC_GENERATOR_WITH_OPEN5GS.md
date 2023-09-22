# 5GC traffic generator with OAI

## Pre-requisites

1. [Setup openstack]()
2. [Create virtual machines for 5gc-tg and Open5gs]()
3. Docker account to download OAI docker images

## Install 5gc-tg

First ssh into the virtual machine you created for the traffic generator. To install the traffic generator follow the instructions in the README file [here]()

## Install OAI core network

First ssh into the virtual machine you created for the core network. We install following the instruction from the Open5gs documentation [here](https://open5gs.org/open5gs/docs/guide/01-quickstart/)

> Note: The installation instruction below might change, check out the Free5gc for the latest instructions.

### Getting MongoDB

```bash
sudo apt update
sudo apt install gnupg
curl -fsSL https://pgp.mongodb.com/server-6.0.asc | sudo gpg -o /usr/share/keyrings/mongodb-server-6.0.gpg --dearmor
```

Install

```bash
sudo apt install -y mongodb

sudo add-apt-repository -y ppa:open5gs/latest

sudo apt update

sudo apt install open5gs
```

### Initialise Open5gs database

Open5gs provides a tool to create UEs. We will use the tool for initialising the database. The tool is not installed when we install open5gs so we have to download it seperately. 

Download open5gs-dbctl

```bash
cd ~/

wget https://raw.githubusercontent.com/open5gs/open5gs/main/misc/db/open5gs-dbctl

chmod +x open5gs-dbctl
```

Initialise db

```bash
imsi=999700000000001

for i in {1..800}
do
    ./open5gs-dbctl add  $[imsi + i] 465B5CE8B199B49FAA5F0A2EE238A6BC E8ED289DEBA952E4283B54E88E6183CA
    echo "Registered IMSI $[imsi + i] times"
done
```

### Setting Open5gs and cn-tg Parameters

In Open5gs VM, we need to edit two files:

* `/etc/open5gs/amf.yaml`
* `/etc/open5gs/upf.yaml`

change `/etc/open5gs/amf.yaml`:

```bash
nano /etc/open5gs/amf.yaml
```

Replace ngap IP from 127.0.0.5 to ip address of Open5gs VM

```bash
...
amf:
    sbi:
      - addr: 127.0.0.5
        port: 7777
    ngap:
      - addr: 127.0.0.5
```

change `/etc/open5gs/upf.yaml`:

```bash
nano /etc/open5gs/upf.yaml
```

Replace gtpu IP from 127.0.0.7 to ip address of Open5gs VM

```bash
...
upf:
    pfcp:
      - addr: 127.0.0.7
    gtpu:
      - addr: 127.0.0.7
```

### Update the cn-tg settings

Update `~/cn-tg/config/open5gs-ue.yaml` respectively to meet the configurations above.

Update `~/cn-tg/config/open5gs-gnb.yaml` as below.

1. Change the ngapIp IP, as well as the gtpIp IP, from 127.0.0.1 to ip address of cn-tg VM
2. Change the IP in amfConfigs into ip address of free5gc VM
3. Change the fgcMac to MAC address of the free5gc VM

```yaml
...
ngapIp: 127.0.0.1   # gNB's local IP address for N2 Interface (Usually same with local IP)
gtpIp: 127.0.0.1    # gNB's local IP address for N3 Interface (Usually same with local IP)

# List of AMF address information
amfConfigs:
- address: 127.0.0.1

fgcMac: 'fa:16:3e:76:e8:67' # Mac address of the Machine with the core network
```

## Running emulation

Restart Open5gs

```bash
systemctl restart open5gs-amfd open5gs-upfd
```

Start cn-tg

```bash
cd ~/cn-tg
python3 run.py -u config/open5gs-ue.yaml -g config/open5gs-gnb.yaml -vv
```