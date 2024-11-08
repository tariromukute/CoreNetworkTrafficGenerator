#!/bin/bash
# Aktivieren des virtuellen Environments
source /opt/CoreNetworkTrafficGenerator/.venv/bin/activate

# Führen Sie das Python-Skript aus
python3 run.py -u config/oai-cn5g-ue.yaml -g config/oai-cn5g-gnb.yaml -vvv
