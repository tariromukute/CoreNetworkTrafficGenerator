# Use docker to create CoreNetworkTrafficGenerator

## Requirements

1. Docker installed
2. SCTP activated

## Building

```bash
# build image 
sudo docker build -t core-network-traffic-generator:latest .
# run container
sudo docker run --rm --privileged core-network-traffic-generator:latest
```

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
