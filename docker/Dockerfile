FROM ubuntu:24.04

# For installing python without questions
ENV DEBIAN_FRONTEND=noninteractive 

RUN apt-get update && apt-get install -y \
    git \
    python3-dev \
    python3-bpfcc \
    python3.12-venv \
    bpfcc-tools \
    && apt-get install -y linux-headers-$(uname -r) || apt-get install -y linux-headers-generic \
    libbpf-dev \
    clang-14 \
    python3-setuptools \
    build-essential \
    vim \
    libsctp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/CoreNetworkTrafficGenerator
COPY ./config /opt/CoreNetworkTrafficGenerator/config/
COPY ./CryptoMobile /opt/CoreNetworkTrafficGenerator/CryptoMobile/
COPY ./pycrate /opt/CoreNetworkTrafficGenerator/pycrate/
COPY ./src /opt/CoreNetworkTrafficGenerator/src/
COPY ./sctptrace /opt/CoreNetworkTrafficGenerator/sctptrace/
COPY ./run.py /opt/CoreNetworkTrafficGenerator/run.py

RUN python3 -m venv --system-site-packages /opt/CoreNetworkTrafficGenerator/.venv

RUN /bin/bash -c "source .venv/bin/activate && \
    pip install --upgrade pip setuptools && \
    pip install pycrate tabulate scapy psutil bcc pytest pyroute2 pysctp cryptography pyyaml netifaces"

RUN /bin/bash -c "source .venv/bin/activate && \
    cd CryptoMobile && \
    python3 setup.py install"

# Create dir for logs
RUN mkdir /var/log/CoreNetworkTrafficGenerator

# Entrypoint script to run at container initialization
COPY ./docker/run.sh /opt/CoreNetworkTrafficGenerator/run.sh
RUN chmod +x /opt/CoreNetworkTrafficGenerator/run.sh
WORKDIR /opt/CoreNetworkTrafficGenerator
ENTRYPOINT ["/opt/CoreNetworkTrafficGenerator/run.sh"]
CMD [ "python3", "run.py", "-vvv" ]