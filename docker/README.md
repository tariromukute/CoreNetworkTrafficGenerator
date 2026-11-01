# Use docker to create CoreNetworkTrafficGenerator

## Requirements

1. Docker installed
2. SCTP activated
3. Host kernel headers installed for the running kernel, for example `linux-headers-$(uname -r)`
4. Host kernel paths mounted into the container when SCTP tracers are enabled

## Building

```bash
# build image 
docker build -t core-network-traffic-generator:latest --file docker/dockerfile .
# run container
docker run --rm --privileged \
	-v /lib/modules:/lib/modules:ro \
	-v /usr/src:/usr/src:ro \
	-v /sys/kernel/debug:/sys/kernel/debug:rw \
	core-network-traffic-generator:latest
```

If the host does not have matching headers for `uname -r`, the SCTP eBPF tracers will be skipped and the traffic generator will continue without them.

## Usage

### Docker

To use a custom config for running the container copy them into the container at building time in the [dockerfile](dockerfile).

### K8s

To use a custom config use K8s Volumes to mount them on the path defined in [run.sh](run.sh).

```yaml
volumeMounts:
- name: oai-config
mountPath: /opt/CoreNetworkTrafficGenerator/config
```
