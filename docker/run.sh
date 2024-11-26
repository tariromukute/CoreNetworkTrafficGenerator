#!/bin/bash
# Aktivieren des virtuellen Environments
source /opt/CoreNetworkTrafficGenerator/.venv/bin/activate

exec "$@"
