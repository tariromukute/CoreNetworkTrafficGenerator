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
