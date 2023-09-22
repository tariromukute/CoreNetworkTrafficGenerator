# 5GC traffic generator with Free5gc

## Pre-requisites

1. [Setup openstack]()
2. [Create virtual machines for 5gc-tg and Free5gc]()
3. 5.4.x version of the Linux kernel for Free5gc

## Install 5gc-tg

First ssh into the virtual machine you created for the traffic generator. To install the traffic generator follow the instructions in the README file [here]()

## Install Free5gc core network

First ssh into the virtual machine you created for the core network. We install following the instruction from the Free5gc documentation [here](https://free5gc.org/guide/3-install-free5gc/)

> Note: The installation instruction below might change, check out the Free5gc for the latest instructions.

### Install Go

Check Go version, Go version must be 1.17.8

```bash
go version
```

If another version of Go is installed, remove the existing version and install Go 1.17.8:

```bash
# this assumes your current version of Go is in the default location
sudo rm -rf /usr/local/go
wget https://dl.google.com/go/go1.17.8.linux-amd64.tar.gz
sudo tar -C /usr/local -zxvf go1.17.8.linux-amd64.tar.gz
```

If Go is not installed on your system

```bash
wget https://dl.google.com/go/go1.17.8.linux-amd64.tar.gz
sudo tar -C /usr/local -zxvf go1.17.8.linux-amd64.tar.gz
mkdir -p ~/go/{bin,pkg,src}
# The following assume that your shell is bash
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin:$GOROOT/bin' >> ~/.bashrc
echo 'export GO111MODULE=auto' >> ~/.bashrc
source ~/.bashrc
```

### Control-plane Supporting Packages

```bash
sudo apt -y update
sudo apt -y install mongodb wget git
sudo systemctl start mongodb
```

### Linux Host Network Settings

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o <dn_interface> -j MASQUERADE
sudo iptables -A FORWARD -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss 1400
sudo systemctl stop ufw
```

### Install Control Plane Elements

```bash
cd ~
git clone --recursive -b v3.3.0 -j `nproc` https://github.com/free5gc/free5gc.git
cd free5gc

# Build all network functions
cd ~/free5gc
make

# Retrieve the 5G GTP-U kernel module using git and build it
git clone -b v0.8.1 https://github.com/free5gc/gtp5g.git
cd gtp5g
make
sudo make install
```

### Initialise Free5gc database

In order to load test we need to create UEs in the database. Under the `assets/free5gc` folder you will find a database dump with UEs, (upload with `scp -r docs/assets/free5gc/dump user@172.24.4.38:/home/ubuntu/free5gc`) you can use the files to initialise your data with `mongorestore  dump/`. Optionally create the webconsole and use the webconsole API to create the users. This is a bit of a hack, future changes might have the work around not working.

Install webconsole

```bash
sudo apt remove cmdtest
sudo apt remove yarn
curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
curl -sL https://deb.nodesource.com/setup_12.x | sudo -E bash -
sudo apt-get update
sudo apt-get install -y nodejs yarn

# Make
cd ~/free5gc
make webconsole

# Run webconsole
cd ~/free5gc/webconsole
go run server.go
```

In a seperate terminal call the webconsole POST endpoint for creating UEs. Create a for loop to create multiple UEs.

```python
import http.client
import json

imsi="imsi-208930000000012"
base_url = "<base_url>:5000"

conn = http.client.HTTPConnection(base_url)


payload = {
    "plmnID": "20893",
    "ueId": imsi,
    "AuthenticationSubscription": {
        "authenticationManagementField": "8000",
        "authenticationMethod": "5G_AKA",
        "milenage": {"op": {
                "encryptionAlgorithm": 0,
                "encryptionKey": 0,
                "opValue": "8e27b6af0e692e750f32667a3b14605d"
            }},
        "opc": {
            "encryptionAlgorithm": 0,
            "encryptionKey": 0,
            "opcValue": ""
        },
        "permanentKey": {
            "encryptionAlgorithm": 0,
            "encryptionKey": 0,
            "permanentKeyValue": "8baf473f2f8fd09487cccbd7097c6862"
        },
        "sequenceNumber": "16f3b3f70fc2"
    },
    "AccessAndMobilitySubscriptionData": {
        "gpsis": ["msisdn-0900000000"],
        "nssai": {
            "defaultSingleNssais": [
                {
                    "sst": 1,
                    "sd": "010203",
                    "isDefault": True
                },
                {
                    "sst": 1,
                    "sd": "112233",
                    "isDefault": True
                }
            ],
            "singleNssais": []
        },
        "subscribedUeAmbr": {
            "downlink": "2 Gbps",
            "uplink": "1 Gbps"
        }
    },
    "SessionManagementSubscriptionData": [
        {
            "singleNssai": {
                "sst": 1,
                "sd": "010203"
            },
            "dnnConfigurations": {
                "internet": {
                    "sscModes": {
                        "defaultSscMode": "SSC_MODE_1",
                        "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]
                    },
                    "pduSessionTypes": {
                        "defaultSessionType": "IPV4",
                        "allowedSessionTypes": ["IPV4"]
                    },
                    "sessionAmbr": {
                        "uplink": "200 Mbps",
                        "downlink": "100 Mbps"
                    },
                    "5gQosProfile": {
                        "5qi": 9,
                        "arp": {"priorityLevel": 8},
                        "priorityLevel": 8
                    }
                },
                "internet2": {
                    "sscModes": {
                        "defaultSscMode": "SSC_MODE_1",
                        "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]
                    },
                    "pduSessionTypes": {
                        "defaultSessionType": "IPV4",
                        "allowedSessionTypes": ["IPV4"]
                    },
                    "sessionAmbr": {
                        "uplink": "200 Mbps",
                        "downlink": "100 Mbps"
                    },
                    "5gQosProfile": {
                        "5qi": 9,
                        "arp": {"priorityLevel": 8},
                        "priorityLevel": 8
                    }
                }
            }
        },
        {
            "singleNssai": {
                "sst": 1,
                "sd": "112233"
            },
            "dnnConfigurations": {
                "internet": {
                    "sscModes": {
                        "defaultSscMode": "SSC_MODE_1",
                        "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]
                    },
                    "pduSessionTypes": {
                        "defaultSessionType": "IPV4",
                        "allowedSessionTypes": ["IPV4"]
                    },
                    "sessionAmbr": {
                        "uplink": "200 Mbps",
                        "downlink": "100 Mbps"
                    },
                    "5gQosProfile": {
                        "5qi": 9,
                        "arp": {"priorityLevel": 8},
                        "priorityLevel": 8
                    }
                },
                "internet2": {
                    "sscModes": {
                        "defaultSscMode": "SSC_MODE_1",
                        "allowedSscModes": ["SSC_MODE_2", "SSC_MODE_3"]
                    },
                    "pduSessionTypes": {
                        "defaultSessionType": "IPV4",
                        "allowedSessionTypes": ["IPV4"]
                    },
                    "sessionAmbr": {
                        "uplink": "200 Mbps",
                        "downlink": "100 Mbps"
                    },
                    "5gQosProfile": {
                        "5qi": 9,
                        "arp": {"priorityLevel": 8},
                        "priorityLevel": 8
                    }
                }
            }
        }
    ],
    "SmfSelectionSubscriptionData": {"subscribedSnssaiInfos": {
            "01010203": {"dnnInfos": [{"dnn": "internet"}, {"dnn": "internet2"}]},
            "01112233": {"dnnInfos": [{"dnn": "internet"}, {"dnn": "internet2"}]}
        }},
    "AmPolicyData": {"subscCats": ["free5gc"]},
    "SmPolicyData": {"smPolicySnssaiData": {
            "01010203": {
                "snssai": {
                    "sst": 1,
                    "sd": "010203"
                },
                "smPolicyDnnData": {
                    "internet": {"dnn": "internet"},
                    "internet2": {"dnn": "internet2"}
                }
            },
            "01112233": {
                "snssai": {
                    "sst": 1,
                    "sd": "112233"
                },
                "smPolicyDnnData": {
                    "internet": {"dnn": "internet"},
                    "internet2": {"dnn": "internet2"}
                }
            }
        }},
    "FlowRules": []
}

payload = json.dumps(payload)
headers = {
    'Accept': "application/json",
    'Accept-Language': "en-GB,en-US;q=0.9,en;q=0.8",
    'Connection': "keep-alive",
    'Content-Type': "application/json;charset=UTF-8",
    'Token': "admin"
    }

conn.request("POST", "/api/subscriber/{}/20893".format(imsi), payload, headers)

res = conn.getresponse()
data = res.read()

print(data.decode("utf-8"))
```

### Setting free5GC and cn-tg Parameters

In free5gc VM, we need to edit three files:

* `~/free5gc/config/amfcfg.yaml`
* `~/free5gc/config/smfcfg.yaml`
* `~/free5gc/config/upfcfg.yaml`

change `~/free5gc/config/amfcfg.yaml`:

```bash
cd ~/free5gc
nano config/amfcfg.yaml
```

Replace ngapIpList IP from 127.0.0.1 to ip address of free5gc VM

```bash
...
ngapIpList:  # the IP list of N2 interfaces on this AMF
- 127.0.0.1
```

change `~/free5gc/config/smfcfg.yaml`:

```bash
nano config/smfcfg.yaml
```

In the entry inside userplane_information / up_nodes / UPF / interfaces / endpoints, change the IP from 127.0.0.8 to ip address of free5gc VM

```yaml
...
interfaces: # Interface list for this UPF
- interfaceType: N3 # the type of the interface (N3 or N9)
    endpoints: # the IP address of this N3/N9 interface on this UPF
    - 127.0.0.8
```

Edit ~/free5gc/config/upfcfg.yaml，and chage gtpu IP from 127.0.0.8 into ip address of free5gc VM

```yaml
...
  gtpu:
    forwarder: gtp5g
    # The IP list of the N3/N9 interfaces on this UPF
    # If there are multiple connection, set addr to 0.0.0.0 or list all the addresses
    ifList:
      - addr: 127.0.0.8
        type: N3
```

### Update the cn-tg settings

Update `~/cn-tg/config/free5gc-ue.yaml` respectively to meet the configurations above.

Update `~/cn-tg/config/free5gc-gnb.yaml` as below.

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

If you have rebooted free5gc, remember to do:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A POSTROUTING -o <dn_interface> -j MASQUERADE
sudo systemctl stop ufw
sudo iptables -I FORWARD 1 -j ACCEPT
```

Start free5gc

```bash
cd ~/free5gc
./run.sh
```

Start cn-tg

```bash
cd ~/cn-tg
python3 run.py -u config/free5gc-ue.yaml -g config/free5gc-gnb.yaml -vv
```
