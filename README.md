# Mobile core network traffic generator

A comprehensive traffic generator for 5G Core Network testing with features for UE/gNodeB emulation, control/user plane traffic generation, SCTP protocol analysis, and 5GC compliance validation.

## Features

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

SCTP Analysis Features
1. Round Trip Time (RTT) measurement
2. Retransmission Timeout (RTO) monitoring
3. Buffer utilisation tracking
4. Stream usage analysis
5. Inter-packet jitter measurement

## Architecture

<p align="center">
  <img src="images/ARCHITECTURE.png" width="350" alt="Core Network Traffic Generator diagram">
</p>

## Installing 5GC traffic generator

```bash
# Get dependencies
git submodule init && git submodule update

# Install required packages
sudo apt-get install python3-dev python3-bpfcc bpfcc-tools linux-headers-$(uname -r) libbpf-dev clang-14 python3-setuptools build-essential
sudo ln /usr/bin/clang-14 /usr/bin/clang

# Install Python packages
pip install pycrate pysctp scapy pyroute2 cryptography pyyaml tabulate

# Install CryptoMobile
cd CryptoMobile && python3 setup.py install
```

## Running the traffic generator

You will need to update the ip address in the files `src/config/open5gs-ue.yaml` and  `src/config/open5gs-gnb.yaml` on the core network VM. The config files are inspired by [UERANSIM](https://github.com/aligungr/UERANSIM)'s config files.


**Configuring the traffic generator to send IP packets**

After PDU session establishment, the traffic generator can generate and send UP traffic for each UE that has established a PDU session. This is achieved by updating the procedures list to include `5GSMPDUSessionTransmission` after `5GSMPDUSessionEstabRequest`, see the sample below. The generator will generate at most the number of packets per second provided above. The default is (1 << 20), meaning it will generate the most it can.

```yaml
...
    # Procedures: a list of UE initiated messages that trigger a given procedure
    procedures:
      - 5GMMRegistrationRequest
      - 5GSMPDUSessionEstabRequest
      - 5GSMPDUSessionTransmission
      - 5GMMMODeregistrationRequest
```

**The user plane: providers**

What happens to a PDU session once it is up is up to the gNB's user plane providers (`src/userplane`). The gNB hands each session to every configured provider as it comes up, and tells them when the UE's context is released. So UEs can be added, and removed, while others are sending.

| Provider | What it does with a session |
|---|---|
| `xdp` | CN-TG's own GTP-U generator, in an XDP program; the default, configured by `gtpuConfig` |
| `file` | appends it to a JSON-lines file, for a generator that reads them |
| `trex` | gives it a TRex stream of its own, through TRex's stateless Python API |

```yaml
gtpIp: 192.168.72.142            # the downlink address given to the 5GC
userPlane:                       # without it, gtpuConfig configures the xdp provider
  providers:
    - type: file
      path: /var/log/CoreNetworkTrafficGenerator/sessions.jsonl
    - type: trex
      server: 192.168.70.151     # TRex's RPC server (4501)
      port: 0                    # the TRex port on N3
      trexClient: /opt/trex-client   # TRex's automation/trex_control_plane/interactive and external_libs
      srcIp: 192.168.72.142      # outer source (TRex's N3 address)
      dstIp: 10.50.73.135        # inner destination
      pps: 1000                  # per session
      payload: 1400
      sequence: true             # a frame counter in the first 4 payload bytes
      sample: 0                  # only the first K sessions get a stream (0: all)
```

How the providers run:
- **The user plane process.** The providers run in a process of their own, fed by the gNB processes through a queue, so a slow provider never holds up NGAP. A provider that fails is logged; the others carry on.
- **The `file` provider.** Each line holds:
  - `supi`, `ue_ip` and `pdu_session_id`;
  - `ul_teid`, `qfi` and `upf_address`;
  - `dl_teid` and `gnb_address`;
  - the NGAP UE IDs and the time.
- **The `trex` provider.**
  - **Profiles.** Each session is a TRex profile of its own (`0.s<ran_ue_ngap_id>_<pdu_session_id>`), so it starts and stops while the others keep sending.
  - **Isolation.** TRex's client brings its own scapy, so the provider drives it from a worker (`trex_worker.py`) in an isolated interpreter. It works with TRex 3.06's client on Python 3.12.
  - **Log.** `log` records when each stream started and stopped.
- **The `xdp` provider** loads `src/bpf/xdpgen.bpf.c` and needs `src/bpf/libxdpgen.so` built from `xdpgen.c`. It cannot remove a session.
- **A new provider** (tc-gtpu, a hardware generator ...) implements `UserPlaneProvider` (`src/userplane/base.py`), and is named as `type: package.module:Class`.

Related options:
- `-i SECONDS` paces the UEs' start;
- `--gnbs N` sets the number of gNB processes (default: one per CPU, less one);
- SIGTERM (`docker stop`) ends the run like Ctrl-C: the UEs write their procedure times first, and the providers stop their traffic.

The DNN and S-NSSAI of the PDU session come from the UE profile's `sessions` entry (`apn`, `slice`), as in UERANSIM.

## Running the traffic generator using Docker Compose

You can also run the traffic generator using Docker Compose, which simplifies the process of setting up and running the required dependencies. Here's an example of how to run it with OAI CN and Free5GC:

**OAI CN**

```bash
cd docker-compose

docker compose -f docker-compose-oai.yaml  --profile oai up -d

# Wait ~10 seconds for UEs to be initiased in DB
docker compose -f docker-compose-oai.yaml  --profile cn-tg up -d

# See the logs with the NGAP and NAS messages
docker logs cn-tg
```

**free5GC**

```bash
cd docker-compose

docker compose -f docker-compose-free5gc.yaml  --profile free5gc up -d

# Wait ~10 seconds for UEs to be initiased in DB
docker compose -f docker-compose-free5gc.yaml  --profile cn-tg up -d

# See the logs with the NGAP and NAS messages
docker logs cn-tg
```

## Output

The traffic generator records the timestamp for each state transition for the UEs. This can be useful for analysing the performance of the Core Network, the computation cost of each prodecure, among other things. When the traffic genetaor exists, this information is stored in files `procedure_times_{cpu}` (since each CPU will act an an independent gNB). The SCTP tracing tools generate data that can be visualised to understand protocol behavior.

Below is a sample result analysis you can extract from the information.

<p align="center">
  <img src="docs/results/cummulative_requests_by_name.png" width="350" alt="Cummulative requests by Procedure Operation Name">
  <img src="docs/results/active_requests_by_name.png" width="350" alt="Active requests by Procedure Operation Name">
  <img src="docs/results/total_active_requests.png" width="350" alt="Total active requests by Procedure Operation Name">
  <img src="docs/results/rtt_correlation_plot.png" width="350" alt="SCTP Round Trip Time Analysis">
  <img src="docs/results/buffutil_avg_util_vs_ues.png" width="350" alt="SCTP Buffer Utilization">
  <!-- <img src="docs/results/sctp_stream_usage.png" width="350" alt="SCTP Stream Usage Patterns"> -->
  <img src="docs/results/jitter_correlation_plot.png" width="350" alt="SCTP Inter-Packet Jitter">
  <img src="docs/results/rto_box_plots_unscaled.png" width="350" alt="SCTP Retransmission Events">
</p>

## Validation/Compliance testing of 5GC responses

The traffic generator can be used to validate responses from the core network. The response data is checked against what's stated in the 3GPP TS 24.501 version 15.7.0. To start validate increase the verbose of the generator: `vvvv` will print only failed validations and `vvvvv` will print all the validation results.

## Notes

For a tutorial on how to run or test the traffic generator with open source 5G networks see the [Performance study of Open Source 5G Core networks](docs/PERFORMANCE_STUDY_OF_5G_CORES.md) under docs folder.
