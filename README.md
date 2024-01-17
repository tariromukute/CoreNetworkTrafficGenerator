# Mobile core network traffic generator

The project implements a traffic generator for 5G Core Network. The traffic generator has the following features:
1. UE emulation - mobile phone
2. gNodeB emulation - NGAP layer
3. gNodeB emulation - GTPU protocol
4. Load testing of control traffic
5. Load testing of user plane traffic
6. Validation/Compliance testing of 5GC responses (WIP)

UE Features
1. Initial registration
2. Primary Authentication and Key Agreement
2. Security Mode Control
3. UE initiated PDU session establishment
3. UE initiated De-registration

NGAP Features
1. NG Setup
2. Initial Context Setup
3. Initial UE Message
4. Downlink NAS Transport
5. Uplink NAS Transport
6. PDU Session Resource Setup
7. UE Connection Release

## Installing 5GC traffic generator

```bash
# initialize your local configuration file
git submodule init
# fetch all the data from that submodule
git submodule update
```

- pycrate `pip install pycrate`
- headers for pysctp `sudo apt-get install python3-dev`
- pysctp `pip install pysctp`
- scapy `pip install scapy`
- bcc `sudo apt-get install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)`
- libbpf `sudo apt-get install libbpf-dev`
- clang `sudo apt-get install clang-14 && sudo ln /usr/bin/clang-14 /usr/bin/clang`
- setuptools `sudo apt install python3-setuptools`
- CryptoMobile (See the submodule for installation)
    - `pip install cryptography`
    - `sudo apt-get install build-essential`
    - `cd CryptoMobile && python3 setup.py install`
- pyyaml `pip install pyyaml`
- tabulate `pip install tabulate`
- matplotlib `pip install matplotlib`

## Running the traffic generator

You will need to update the ip address in the files `src/config/open5gs-ue.yaml` and  `src/config/open5gs-gnb.yaml` on the core network VM. The config files are inspired by [UERANSIM](https://github.com/aligungr/UERANSIM)'s config files.

```bash
cd ~/cn-tg/

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
#   -s, --statistics      Enable print of statistics
#   -e, --ebpf            Load ebpf programs to collect and graph SCTP stats

python3 run.py -u config/oai-cn5g-ue.yaml -g config/oai-cn5g-gnb.yaml -vvv
```

### Sending user plane traffic

There are two options to sending the traffic:
1. Configuring the traffic generator to send IP packets
2. Using the `ue_send.py` script to send traffic

**Configuring the traffic generator to send IP packets**

After PDU session establishment, the traffic generator can generate and send UP traffic for each UE that has established a PDU session. This is achieved by updating the procedures list to include `5GUPMessage` after `5GSMPDUSessionEstabRequest`, see the sample below. The User Plane data and count should then be provide. The upData is scapy's IP packet in bytes, see below a sample on how to the generate the IP packet using scapy. The IP header will be updated respectively by the traffic generator before sending the packets i.e., the IP source address and the checksum.

```yaml
...
    # Procedures: a list of UE initiated messages that trigger a given procedure
    procedures:
      - 5GMMRegistrationRequest
      - 5GSMPDUSessionEstabRequest
      - 5GUPMessage
      - 5GMMMODeregistrationRequest

    upData: '4500001c00010000400160c10a000010080808080800f7ff00000000'
    upCount: 5
```

Generate the IP packet using scapy

```python
from scapy.all import *
import binascii

ip_pkt = IP(dst="8.8.8.8")/ICMP()
raw_ip_pkt = raw(ip_pkt)
hex_ip_pkt = binascii.hexlify(raw_ip_pkt)
print(hex_ip_pkt)
```

**Using the `ue_send.py` script to send traffic**

To send UE traffic using the `ue_send.py` make sure `5GSMPDUSessionEstabRequest` is the last entry under procedures in the UE config file, if `5GMMMODeregistrationRequest` follows afterwards the session will be terminated.

You can send UE traffic using the script `ue_send.py`. The scripts makes use of scapy to compose traffic to send to the core network dataplane. By default it sends a ICMP echo request to 8.8.8.8, you can modify the packet by passing an IP packet in hex format. You can generate the IP packet using scapy, see the example above.

You can the send the packets by passing the parameters displayed during PDU session establishment

```bash
# Check `python3 ue_send.py --help` for description of arguments
python3 ue_send.py -d 192.168.70.134 -m 'fa:16:3e:d8:d9:80' -s 12.1.1.35 -q 9 -t 35 -u 5 -i 1000 -p <hex_ip_pkt>
```

Enable the python to send packets with Scapy with non-root user

```bash
# find original file is execute shell command
ls -la /usr/bin/python3
# set capabilities for binaries running your script
sudo setcap cap_net_raw=eip /usr/bin/python3.8
```

## Validation/Compliance testing of 5GC responses

The traffic generator can be used to validate responses from the core network. The response data is checked against what's stated in the 3GPP TS 24.501 version 15.7.0. To start validate increase the verbose of the generator: `vvvv` will print only failed validations and `vvvvv` will print all the validation results.

## Notes

For a tutorial on how to run or test the traffic generator with open source 5G networks see the [Performance study of Open Source 5G Core networks](docs/PERFORMANCE_STUDY_OF_5G_CORES.md) under docs folder.