# 5GC traffic generator with OAI

## Pre-requisites

1. [Setup openstack]()
2. [Create virtual machines for 5gc-tg and OAI]()
3. Docker account to download OAI docker images

## Install 5gc-tg

First ssh into the virtual machine you created for the traffic generator. To install the traffic generator follow the instructions in the README file [here]()

## Install OAI core network

First ssh into the virtual machine you created for the core network. We install following the instruction from the OAI documentation [here]()

```bash
# x> AMF
git clone -b develop https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-amf.git
cd oai-cn5g-amf/build/scripts

# Install dependencies
sudo ./build_amf --install-deps --force

# Install AMF
sudo ./build_amf --clean --Verbose --build-type Release --jobs

# x> SMF
git clone -b develop https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-smf.git
cd oai-cn5g-smf/build/scripts

# Install dependencies
sudo ./build_smf --install-deps --force

# Install SMF
sudo ./build_smf --clean --Verbose --build-type Release --jobs

# x> UDR
git clone -b develop https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-udr.git
cd oai-cn5g-udr/build/scripts

# Install dependencies
sudo ./build_udr --install-deps --force

# Install UDR
sudo ./build_udr --clean --Verbose --build-type Release --jobs

# x> UDM
git clone -b develop https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-udm.git
cd oai-cn5g-udm/build/scripts

# Install dependencies
sudo ./build_udm --install-deps --force

# Install UDM
sudo ./build_udm --clean --Verbose --build-type Release --jobs

# x> AUSF
git clone -b develop https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-ausf.git
cd oai-cn5g-ausf/build/scripts

# Install dependencies
sudo ./build_ausf --install-deps --force

# Install AUSF
sudo ./build_ausf --clean --Verbose --build-type Release --jobs

# x> NRF
git clone -b develop https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-nrf.git
cd oai-cn5g-nrf/build/scripts

# Install dependencies
sudo ./build_nrf --install-deps --force

# Install NRF
sudo ./build_nrf --clean --Verbose --build-type Release --jobs

# x> SPGWU
git clone https://gitlab.eurecom.fr/oai/cn5g/oai-cn5g-upf.git
cd oai-cn5g-upf/build/scripts

# Install dependencies
sudo ./build_upf --install-deps --force

# Install SPGWU
sudo ./build_upf --clean --Verbose --build-type Release --jobs
```

Install Mysql

```bash
sudo apt install mysql-client mysql-server

# Create db and user
sudo mysql -u root -p
```

```sql
CREATE DATABASE oai_db;
CREATE USER 'test'@'%' IDENTIFIED BY 'test';
GRANT ALL PRIVILEGES ON oai_db.* TO 'test'@'%'; 
FLUSH PRIVILEGES;
exit
```

Initialise db

```bash
# Upload the db dump (from another machine)
scp -r docs/assets/oai/oai_db_load.sql user@172.24.4.88:/home/ubuntu/conf

# Restore database dump
mysql -u test -p oai_db < oai_db_load.sql
```

### Start core network

To run the network functions in the background we created service files for them. Copy the files under `docs/assets/oai/services` to the OAI VM under `/lib/systemd/system/`

Copy the config file `docs/assets/oai/basic_nrf_config.yaml` to `/etc/oai/config.yaml` under the OAI VM

Update n2 interface_name with the OAI VM interface name

```yaml
nfs:
  amf:
    host: oai-amf
    sbi:
      port: 8080
      api_version: v1
      interface_name: lo:132
    n2:
      interface_name: ens3
      port: 38412
```

Create oai-cn5g hostnames in `/etc/hosts`. You can utilise the helper script under `docs/assets/oai/netconf.sh`.

### Running emulation

Start oai-cn5g

```bash
sudo systemctl restart oai-cn5g-nrfd oai-cn5g-udrd oai-cn5g-udmd oai-cn5g-ausfd oai-cn5g-amfd oai-cn5g-smfd oai-cn5g-upfd 
```

Start cn-tg

```bash
cd ~/cn-tg
python3 run.py -u config/open5gs-ue.yaml -g config/open5gs-gnb.yaml -vv
```

Get logs
```bash
journalctl -u oai-* -n 200
```