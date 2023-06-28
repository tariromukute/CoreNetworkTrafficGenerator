#!/bin/bash

# Set the number of times to run the scripts
RUNS=5

# Set the number of minutes to wait between runs
DELAY=1

for ((i=1; i<=RUNS; i++))
do
    # Wait for the specified delay between runs
    echo "Starting sleep"
    sleep $((DELAY * 60))

    # Start the Python script in the background and redirect its output to a file
    echo "Starting cn-tg"
    .venv/bin/python3 src/app.py -t 60 -i 0 -n $((i * 10)) -f /tmp/core-tg -u src/config/free5gc-ue.yaml -g src/config/free5gc-gnb.yaml >> python_output.txt &

    # Get the process ID of the Python script
    PYTHON_PID=$!

    # Start the bpftrace program in the background and redirect its output to a file
    echo "Starting bpftrace"
    echo $i >> bpftrace_output.txt
    bpftrace sctprtt.bt >> bpftrace_output.txt &

    # Get the process ID of the bpftrace program
    BPFTRACE_PID=$!

    # Set the number of minutes to wait before terminating the scripts
    MINUTES=1

    # Wait for the specified number of minutes
    sleep $((MINUTES * 40))

    # Terminate the Python script and bpftrace program
    echo "Ending program"
    kill -SIGINT $PYTHON_PID $BPFTRACE_PID
done