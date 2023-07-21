# Mobile core network traffic generator

## Requirements

```bash
# initialize your local configuration file
git submodule init
# fetch all the data from that submodule
git submodule update
```

- pycrate `pip install pycrate`
- headers for pysctp `sudo apt-get install python3-dev`
- pysctp `pip install pysctp`
- CryptoMobile (See the submodule for installation)
    - `pip install cryptography`
    - `sudo apt-get install build-essential`
    - `cd CryptoMobile && python3 setup.py install`
- pyyaml `pip install pyyaml`

## Running the traffic generator

You will need to update the ip address in the files `src/config/open5gs-ue.yaml` and  `src/config/open5gs-gnb.yaml` on the core network VM. The config files are inspired by [UERANSIM](https://github.com/aligungr/UERANSIM)'s config files.

```bash
cd ~/cn-tg/
source .venv/bin/activate

# usage: run.py [-h] [-i INTERVAL] [-u UE_CONFIG_FILE] [-g GNB_CONFIG_FILE] [-f FILE] [-v]

# Run 5G Core traffic generator

# optional arguments:
#   -h, --help            show this help message and exit
#   -i INTERVAL, --interval INTERVAL
#                         Interval of adding UEs in seconds
#   -u UE_CONFIG_FILE, --ue_config_file UE_CONFIG_FILE
#                         UE configuration file
#   -g GNB_CONFIG_FILE, --gnb_config_file GNB_CONFIG_FILE
#                         GNB configuration file
#   -f FILE, --file FILE  Log file directory
#   -v, --verbose         Increase verbosity (can be specified multiple times)

python3 src/run.py -u config/open5gs-ue.yaml -g config/open5gs-gnb.yaml -vvv
```

## Using dataplane

To send UE traffic make sure `5GSMPDUSessionEstabRequest` is the last entry under procedures in the UE config file, if `5GMMMODeregistrationRequest` follows afterwards the session will be terminated.

You can send UE traffic using the script `ue_send.py`. The scripts makes use of scapy to compose traffic to send to the core network dataplane. By default it sends a ICMP echo request to 8.8.8.8, you can modify the packet by passing an IP packet in hex format. You can generate the IP packet using scapy, see below.

```python
from scapy.all import *
import binascii

ip_pkt = IP(dst="8.8.8.8")/ICMP()
raw_ip_pkt = raw(ip_pkt)
hex_ip_pkt = binascii.hexlify(raw_ip_pkt)
print(hex_ip_pkt)
```

You can the send the packets by passing the parameters displayed during PDU session establishment

```bash
# Check `python3 ue_send.py --help` for description of arguments
python3 ue_send.py -d 192.168.70.134 -m 'fa:16:3e:d8:d9:80' -s 12.1.1.35 -q 9 -t 35 -u 5 -i 1000 -p <hex_ip_pkt>
```

Enable the python to send packets with Scapy with non-root user\

```bash
# find original file is execute shell command
ls -la /usr/bin/python3
# set capabilities for binaries running your script
sudo setcap cap_net_raw=eip /usr/bin/python3.8
```
## Notes

For a tutorial on how to run or test the traffic generator with open source 5G networks see the [Performance study of Open Source 5G Core networks](docs/PERFORMANCE_STUDY_OF_5G_CORES.md) under docs folder.