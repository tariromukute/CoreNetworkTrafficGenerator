#/!bin/bash

# This script is used to execute the commands in to run ansible ad hoc commands
# and playbooks.

# List of syscalls to inspect
# SYSCALLS="futex epoll_wait recvmsg clock_nanosleep poll select ppoll read openat sendto sched_yield recvfrom"
SYSCALLS="futex"
# Loop through the syscalls and run the ansible ad hoc commands with syscall as parameter
for SYSCALL in $SYSCALLS; do
    ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall '$SYSCALL' -d 20 -L -P -m -j", tool: sysprocess_epoll_wait, ues: 0 }'
done