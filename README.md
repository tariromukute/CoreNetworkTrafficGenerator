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
cd ~/core-tg/
source .venv/bin/activate

# -t : duration of the traffic generator should run for>
# -n : number of UE to register, starting with the UE is IMSI in the ai-cn5g-ue.yaml
# -f : file to write logs to
# -u : config file for UE
# -g : config file for GNB
python3 src/app.py -t 20 -i 0 -n 1 -f /tmp/core-tg -u src/config/open5gs-ue.yaml -g src/config/open5gs-gnb.yaml
```

For a tutorial on how to run or test the traffic generator with open source 5G networks see the [Performance study of Open Source 5G Core networks](docs/PERFORMANCE_STUDY_OF_5G_CORES.md) under docs folder.

```bash
python3 -m cProfile -o perf_ngap.prof src/perf_ngap.py
python3 -m snakeviz perf_ngap.prof -s

py-spy record -o mandelbrot-profile_3.svg -- python3 src/perf_ngap.py
```