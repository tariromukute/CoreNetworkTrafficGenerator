
## Performance Analysis

### Open5gs

**syscount: Syscalls and system processes analysis**

We start by analysis the syscall counts across the system and related process, as well as their latency information. This is very useful for general workload characterization. To get all the available syscalls `sudo python3 syscount.py --list`

Yes, I can. According to 1 and 2, system calls can be grouped roughly into five or six major categories:

Process control: create, terminate, load, execute, get/set process attributes, wait for time/event, signal event, allocate and free memory
File management: create, open, close, delete, read/write file
Device management: request/release device access, read/write device
Information maintenance: get/set system time/date/attributes
Communication: create/delete communication connection, send/receive messages

Services Provided by System Calls :

Process creation and management
Main memory management
File Access, Directory and File system management
Device handling(I/O)
Protection
Networking, etc.

Types of System Calls : There are 5 different categories of system calls –

1. Process control: end, abort, create, terminate, allocate and free memory.
2. File management: create, open, close, delete, read file etc.
3. Device management
4. Information maintenance
5. Communication

We first ran syscalls analysis for an idle system, not receiving any traffic.

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -m -j", tool: syscount, ues: 0 }'
```

![Syscalls across the idle system (by latency)](./assets/syscount_fig_m2.medium_ue_0.jpeg "Syscalls across the idle system (by latency)")
<b>Fig.1 - Syscalls across the idle system (by latency)</b>

<details><summary><b>Click to see results on different instance sizes</b></summary>

We ran the same too on an idle `m1.large` instance and got more or less the same results. The details of the flavous are:
* m2.medium: RAM 4096 |  Disk 50 | vCPU 2
* m1.large: RAM 8192 |  Disk 80 | vCPU 4

![Syscalls across the idle system (by latency)](./assets/syscount_fig_m1.large_ue_0.jpeg "Syscalls across the idle system  on a m1.large instance on devstack (by latency)")
<b>Fig.1.1 - Syscalls across the idle system  on a m1.large instance on devstack (by latency)</b>

</details>

**Process making system calls**

We then looked at the processes making these system calls on the idle system.

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -P -m -j", tool: sysprocess, ues: 0 }'
```

![Processes making syscall on idle system (by latency)](./assets/sysprocess_fig_m2.medium_ue_0.jpeg "Processes making syscall on idle system (by latency)")
<b>Fig.2 - Processes making syscall on idle system (by latency)</b>

<details><summary><b>Click to see results at 90 UEs</b></summary>

![Processes making syscall on idle system (by latency)](./assets/sysprocess_fig_m2.medium_ue_90.jpeg "Processes making syscall on idle system (by latency)")
<b>Fig.2 - Processes making syscall on idle system (by latency)</b>

</details>


**futex**

The open5gs has a lot of futex system calls. Once one the reasons for high futex system calls on VM is high contention on shared-memory resources that causes many threads to wait on futexes <a href="https://access.redhat.com/solutions/534663">source</a>. Therefore a lot of futex system calls on a VM may indicate that there is a lot of concurrent access to shared resources or data structures by multiple threads or processes. Ran the analysis on open5gs system that is not receiving an traffic and we still got active or a lot of syscalls. To get a visibility of the processes producing the futex syscalls we ran `sudo python3 syscount.py --syscall futex -L -P -d 2`, this gave is the results below.

<details><summary><b>Click to see results for processes making futex system calls</b></summary>

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall futex -d 20 -L -P -m -j", tool: sysprocess_futex, ues: 0 }'
```

![Processes making futex syscall on idle system (by latency)](./assets/sysprocess_futex_fig_m2.medium_ue_0.jpeg "Processes making futex syscall on idle system (by latency)")
<b>Fig.3.1 - Processes making futex syscall on idle system (by latency)</b>

```
{'time': '08:36:06', 'pid': 593, 'comm': 'mongod', 'count': 954, 'time (ms)': 208892.335445}
{'time': '08:36:06', 'pid': 6112, 'comm': 'open5gs-smfd', 'count': 234, 'time (ms)': 114015.990154}
{'time': '08:36:06', 'pid': 6110, 'comm': 'open5gs-mmed', 'count': 234, 'time (ms)': 114014.755245}
{'time': '08:36:06', 'pid': 6111, 'comm': 'open5gs-pcrfd', 'count': 234, 'time (ms)': 114014.28929}
{'time': '08:36:06', 'pid': 6113, 'comm': 'open5gs-hssd', 'count': 248, 'time (ms)': 114013.025501}
{'time': '08:36:06', 'pid': 459, 'comm': 'multipathd', 'count': 59, 'time (ms)': 19002.35523}
{'time': '08:36:06', 'pid': 619, 'comm': 'rsyslogd', 'count': 14, 'time (ms)': 15193.089794}
```

![Processes making futex syscall (by latency)](./assets/sysprocess_futex_fig_m2.medium_ue_90.jpeg "Processes making futex syscall (by latency)")
<b>Fig.3.2 - Processes making futex syscall on 90 UEs (by latency) - 20 secs</b>

</details>

For a system not receiving traffic, this points the source of the futex system calls being high contention on shared-memory resources. To reduce this we will need to run the open5gs system on a larger instance.

- [ ] TODO: Verify source of high futex - compare performance of open5gs on different VM instances. Can also compare on hardware server.

**epoll_wait**

The system also has a large epoll_wait system calls when receiving traffic. The possible reasons for this are:

1. You have more file descriptors ready than the maxevents parameter you passed to epoll_wait, and the system call is round-robin through them.
2. You have a signal handler that interrupts epoll_wait and causes it to return with an error code (EINTR). You may need to check for this error and retry the system call.
- To confirm this we ran `sudo python3 syscount.py -x --d 2` which gives a list of failed system calls. epoll_wait was not on the list. Also ran `sudo python3 syscount.py -e EINTR --d 2` to check for processes failing with the above error, of which none were failing.
3. You have a problem with timer handling or scheduling latency across system suspend or resume, which may trigger a watchdog logic that aborts epoll_wait https://github.com/systemd/systemd/issues/23032
4. A lot of epoll_wait system calls on a VM may indicate that there is a lot of I/O activity on the VM or that the timeout value for epoll_wait is too low.

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall epoll_wait -d 20 -L -P -m -j", tool: sysprocess_epoll_wait, ues: 0 }'
```

<details><summary><b>Click to see results for processes making epoll_wait system calls</b></summary>

![Processes making epoll_wait syscall on idle system (by latency)](./assets/sysprocess_epoll_wait_fig_m2.medium_ue_0.jpeg "Processes making epoll_wait syscall on idle system (by latency)")
<b>Fig.3.1 - Processes making epoll_wait syscall on idle system (by latency)</b>

```
{'time': '08:55:09', 'pid': 7108, 'comm': 'python3', 'count': 19, 'time (ms)': 19019.138666}
{'time': '08:55:09', 'pid': 6754, 'comm': 'open5gs-sgwud', 'count': 7, 'time (ms)': 18512.13527}
{'time': '08:55:09', 'pid': 6753, 'comm': 'open5gs-sgwcd', 'count': 7, 'time (ms)': 18512.093091}
{'time': '08:55:09', 'pid': 332, 'comm': 'systemd-journal', 'count': 8, 'time (ms)': 15331.316252}
{'time': '08:55:09', 'pid': 6743, 'comm': 'open5gs-amfd', 'count': 10, 'time (ms)': 13167.852904}
{'time': '08:55:09', 'pid': 6772, 'comm': 'open5gs-smfd', 'count': 9, 'time (ms)': 11502.354285}
{'time': '08:55:09', 'pid': 6747, 'comm': 'open5gs-nrfd', 'count': 54, 'time (ms)': 11020.054314}
{'time': '08:55:09', 'pid': 6748, 'comm': 'open5gs-scpd', 'count': 61, 'time (ms)': 11014.449378}
{'time': '08:55:09', 'pid': 6744, 'comm': 'open5gs-upfd', 'count': 4, 'time (ms)': 11002.410433}
{'time': '08:55:09', 'pid': 6759, 'comm': 'open5gs-bsfd', 'count': 5, 'time (ms)': 10010.64112}
```

![Processes making epoll_wait syscall on idle system (by latency)](./assets/sysprocess_epoll_wait_fig_m2.medium_ue_90.jpeg "Processes making epoll_wait syscall on idle system (by latency)")
<b>Fig.3.1 - Processes making epoll_wait syscall 90 UEs (by latency) - 20 secs</b>

</details>

To understand `sudo python3 tplist.py | grep epoll_wait` and then `sudo python3 tplist.py -v syscalls:sys_enter_epoll_wait`

`sudo python3 argdist.py -C 't:syscalls:sys_exit_epoll_wait():u16:args->ret' -i 5 -d 5`

<details><summary>Click to see results for further investigating the epoll_wait syscalls</summary>

One of the reasons can be that timeouts for epoll_wait are low. This means that the it reaches timeouts when there are few or no events to poll in most cases. To get visibility of this we run inspect the `sys_enter_epoll_wait` and `sys_exit_epoll_wait` tracepoint to trace the value of timeout on most of the epoll_wait syscalls and the number of events to be polled respectively.

We start by using the helper tool `tplist.py` to get more information on the tracepoints `sudo python3 tplist.py | grep epoll_wait` can help filter all the epoll_wait related tracepoints. The commands `sudo python3 tplist.py -v syscalls:sys_enter_epoll_wait` and `sudo python3 tplist.py -v syscalls:sys_exit_epoll_wait` will print the arguments passed to these tracepoint (which are the values we want to inspect).

We start by looking at the value of timeouts using as below

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_enter_epoll_wait():u16:args->timeout' -i 20 -d 20\", tool: sysprocess_enter_epoll_wait_timeout, ues: 0 }"
```

The results from the above were

```
[10:26:30]
t:syscalls:sys_enter_epoll_wait():u16:args->timeout
	COUNT      EVENT
	1          args->timeout = 1494
	1          args->timeout = 30000
	1          args->timeout = 998
	1          args->timeout = 994
	1          args->timeout = 996
	1          args->timeout = 13
	1          args->timeout = 19994
	1          args->timeout = 1996
	1          args->timeout = 2997
	1          args->timeout = 494
	1          args->timeout = 991
	2          args->timeout = 11000
	2          args->timeout = 4529
	2          args->timeout = 69
	2          args->timeout = 8868
	3          args->timeout = 9095
	3          args->timeout = 1678
	3          args->timeout = 1009
	3          args->timeout = 1007
	3          args->timeout = 1043
	3          args->timeout = 1671
	3          args->timeout = 999
	3          args->timeout = 9102
	3          args->timeout = 1033
	3          args->timeout = 1017
	3          args->timeout = 997
	3          args->timeout = 1008
	3          args->timeout = 2470
	3          args->timeout = 1016
	3          args->timeout = 70
	3          args->timeout = 1020
	4          args->timeout = 8851
	4          args->timeout = 60
	4          args->timeout = 7500
	4          args->timeout = 2500
	4          args->timeout = 9991
	4          args->timeout = 8844
	4          args->timeout = 63
	4          args->timeout = 9992
	5          args->timeout = 990
	5          args->timeout = 33
	6          args->timeout = 3493
	6          args->timeout = 43
	6          args->timeout = 2123
	6          args->timeout = 8867
	7          args->timeout = 993
	8          args->timeout = 748
	17         args->timeout = 65535
	19         args->timeout = 10000
	25         args->timeout = 1000
	33         args->timeout = 0
```

We then looked at the exit to get the number of events to be polled on every poll exit

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_epoll_wait():u16:args->ret' -i 20 -d 20\", tool: sysprocess_exit_epoll_wait, ues: 0 }"
```

The results from above were

```
[10:11:31]
t:syscalls:sys_exit_epoll_wait():u16:args->ret
	COUNT      EVENT
	1          args->ret = 3
	1          args->ret = 4
	1          args->ret = 5
	2          args->ret = 6
	5          args->ret = 2
	84         args->ret = 0
	136        args->ret = 1
```

We can see that for the given timeouts in most cases the number of events to be polled were 0 or 1. This is major because we were collecting the results for an idle system. The `epoll_wait` is mainly used for busy systems. In the case were the system is idle it is a 'waste' of resources. However, the system was not meant for cases where it is idle.

In order to get a better evalution of the system usage of the `epoll_wait` we need to  run the test when the system is not idle.

When there are 90 UEs

```
t:syscalls:sys_exit_epoll_wait():u16:args->ret
	COUNT      EVENT
	1          args->ret = 6
	10         args->ret = 5
	41         args->ret = 4
	193        args->ret = 3
	868        args->ret = 2
	1674       args->ret = 0
	13770      args->ret = 1
```
</details>

**recvmsg**

The recvmsg system call is used to receive messages from a socket, and may be used to receive data on a socket. The syscall is used whether or not it is connection-oriented.

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall recvmsg -d 20 -L -P -m -j", tool: sysprocess_recvmsg, ues: 0 }'
```
<details><summary><b>Click to see results for processes making recvmsg system calls</b></summary>

![Processes making recvmsg syscall on idle system (by latency)](./assets/sysprocess_recvmsg_fig_m2.medium_ue_0.jpeg "Processes making recvmsg syscall on idle system (by latency)")
<b>Fig.3.1 - Processes making recvmsg syscall on idle system (by latency)</b>

![Processes making recvmsg syscall on idle system (by latency)](./assets/sysprocess_recvmsg_fig_m2.medium_ue_90.jpeg "Processes making recvmsg syscall 90 UEs (by latency) - 20 secs")
<b>Fig.3.1 - Processes making recvmsg syscall on 90 UEs (by latency) - 20 secs</b>

![Processes making recvmsg syscall on idle system (by latency)](./assets/sysprocess_count_recvmsg_fig_m2.medium_ue_90.jpeg "Processes making recvmsg syscall on idle system 90 UEs (by number of calls) - 20 secs")
<b>Fig.3.1 - Processes making recvmsg syscall on idle system (by latency)</b>

Get tracepoints for recvmsg `sudo python3 tplist.py | grep recvmsg`

Get arguments for recvmsg tracepoints:
* `sudo python3 tplist.py -v syscalls:sys_enter_recvmsg`
* `sudo python3 tplist.py -v syscalls:sys_exit_recvmsg`
</details>

**clock_nanosleep**

clock_nanosleep system calls are functions that allow a thread to sleep for a specified time interval with nanosecond precision <a href="https://man.archlinux.org/man/clock_nanosleep.2.en">source</a>. clock_nanosleep are mainly used by processes to manage their resources and avoid blocking other threads or processes. We see that the main processes using clock_nanosleep are `mongod` and `multipathd`.

`mongod` is a process that runs MongoDB, a cross-platform document-oriented database system and `multipathd` is a daemon that monitors and manages multipath devices on Linux systems. Multipath devices are virtual devices that combine multiple physical connections between a server and a storage array into one logical device

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall clock_nanosleep -d 20 -L -P -m -j", tool: sysprocess_clock_nanosleep, ues: 0 }'
```

<details><summary><b>Click to see results for processes making clock_nanosleep system calls</b></summary>

Results
```json
{'time': '09:16:09', 'pid': 593, 'comm': 'mongod', 'count': 202, 'time (ms)': 35824.511271}
{'time': '09:16:09', 'pid': 459, 'comm': 'multipathd', 'count': 19, 'time (ms)': 19001.301196}

```
</details>

**poll**

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall poll -d 20 -L -P -m -j", tool: sysprocess_poll, ues: 0 }'
```
<details><summary><b>Click to see results for processes making poll system calls</b></summary>

Results
```json
{'time': '09:16:09', 'pid': 593, 'comm': 'mongod', 'count': 202, 'time (ms)': 35824.511271}
{'time': '09:16:09', 'pid': 459, 'comm': 'multipathd', 'count': 19, 'time (ms)': 19001.301196}

```
</details>

**select**

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall select -d 20 -L -P -m -j", tool: sysprocess_select, ues: 0 }'
```
<details><summary><b>Click to see results for processes making select system calls</b></summary>

Results
```json
{'time': '09:35:58', 'pid': 9770, 'comm': 'python3', 'count': 1, 'time (ms)': 20015.606103}
{'time': '09:35:58', 'pid': 9764, 'comm': 'python3', 'count': 3, 'time (ms)': 15011.22589}

```
</details>

**ppoll**

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall ppoll -d 20 -L -P -m -j", tool: sysprocess_ppoll, ues: 0 }'
```

<details><summary><b>Click to see results for processes making ppoll system calls</b></summary>

Results
```json
{'time': '09:40:08', 'pid': 459, 'comm': 'multipathd', 'count': 3, 'time (ms)': 15000.181066}
```
</details>

**read**

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall read -d 20 -L -P -m -j", tool: sysprocess_read, ues: 0 }'
```
<details><summary><b>Click to see results for processes making read system calls</b></summary>

Results
```json
{'time': '09:43:44', 'pid': 593, 'comm': 'mongod', 'count': 240, 'time (ms)': 3.03758}
{'time': '09:43:44', 'pid': 332, 'comm': 'systemd-journal', 'count': 66, 'time (ms)': 0.349825}
{'time': '09:43:44', 'pid': 591, 'comm': 'irqbalance', 'count': 8, 'time (ms)': 0.176016}
{'time': '09:43:44', 'pid': 580, 'comm': 'accounts-daemon', 'count': 20, 'time (ms)': 0.065704}
{'time': '09:43:44', 'pid': 1, 'comm': 'systemd', 'count': 2, 'time (ms)': 0.03521}
{'time': '09:43:44', 'pid': 364, 'comm': 'systemd-udevd', 'count': 7, 'time (ms)': 0.026194}
{'time': '09:43:44', 'pid': 617, 'comm': 'node', 'count': 4, 'time (ms)': 0.020493}
{'time': '09:43:44', 'pid': 10701, 'comm': 'open5gs-upfd', 'count': 1, 'time (ms)': 0.010628}
{'time': '09:43:44', 'pid': 540, 'comm': 'systemd-network', 'count': 1, 'time (ms)': 0.007948}
{'time': '09:43:44', 'pid': 10921, 'comm': '[unknown]', 'count': 1, 'time (ms)': 0.00566}
```
</details>

**openat**

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall openat -d 20 -L -P -m -j", tool: sysprocess_openat, ues: 0 }'
```
<details><summary><b>Click to see results for processes making openat system calls</b></summary>

Results
```json
{'time': '09:49:18', 'pid': 593, 'comm': 'mongod', 'count': 179, 'time (ms)': 2.140478}
{'time': '09:49:18', 'pid': 332, 'comm': 'systemd-journal', 'count': 50, 'time (ms)': 0.370852}
{'time': '09:49:18', 'pid': 591, 'comm': 'irqbalance', 'count': 10, 'time (ms)': 0.078661}
{'time': '09:49:18', 'pid': 364, 'comm': 'systemd-udevd', 'count': 2, 'time (ms)': 0.026813}
{'time': '09:49:18', 'pid': 1, 'comm': 'systemd', 'count': 1, 'time (ms)': 0.025125}
```
</details>

**sendto**

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall sendto -d 20 -L -P -m -j", tool: sysprocess_sendto, ues: 0 }'
```
<details><summary><b>Click to see results for processes making sendto system calls</b></summary>


</details>

**sched_yield**

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall sched_yield -d 20 -L -P -m -j", tool: sysprocess_sched_yield, ues: 0 }'
```

<details><summary><b>Click to see results for processes making sched_yield system calls</b></summary>

Results
```json

```
</details>

**recvfrom**

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall recvfrom -d 20 -L -P -m -j", tool: sysprocess_recvfrom, ues: 0 }'
```

<details><summary><b>Click to see results for processes making recvfrom system calls</b></summary>

Results
```json

```
</details>

## System call categorisation

System calls can be grouped roughly into five major categories:

- Process control: These system calls perform the task of process creation, termination, execution, loading, etc. They also handle memory allocation and deallocation for processes.
- File management: These system calls handle file manipulation jobs like creating, opening, closing, deleting, reading, writing, renaming files and directories. They also manage file attributes and permissions.
- Device management: These system calls do the job of requesting and releasing access to devices such as disks, printers, scanners, etc. They also control device functions such as reading and writing data from or to devices.
- Information maintenance: These system calls provide information about various system resources such as time, date, user identity, process status, etc. They also allow modifying some system parameters such as priority levels.
- Communication: These system calls enable processes to communicate with each other using various methods such as message passing or shared memory. They also support network communication using sockets or pipes.

To see the list of system calls on Linux run `sudo python3 syscount.py --list`.

<details><summary><b>Click to see the system calls categorised by type</b></summary>

System Call | Type | Details
---|---|---
_sysctl                  | -            | x
accept                   | -            | x
accept4                  | -            | x
access                | -           | x
acct                     | -            | x
add_key                  | -            | x
adjtimex                 | -            | x
afs_syscall           | -           | x
alarm                    | -            | x
arch_prctl               | -            | x
bind                     | -            | x
bpf                   | -           | x
brk                      | -            | x
capget                   | -            | x
capset                   | -            | x
chdir                 | -           | x
chmod                    | -            | x
chown                    | -            | x
chroot                   | -            | x
clock_adjtime         | -           | x
clock_getres             | -            | x
clock_gettime            | -            | x
clock_nanosleep          | P            | Enables processes to control their execution time and behavior. It helps processes manage their resources and avoid blocking other threads or processes.
clock_settime         | -           | x
clone                    | -            | x
close                    | -            | x
connect                  | -            | x
copy_file_range       | -           | x
creat                    | -            | x
create_module            | -            | x
delete_module            | -            | x
dup                   | -           | x
dup2                     | -            | x
dup3                     | -            | x
epoll_create             | -            | x
epoll_create1         | -           | x
epoll_ctl                | -            | x
epoll_ctl_old            | -            | x
epoll_pwait              | -            | x
epoll_wait            | C           | Waits for events on an epoll instance referred to by a file descriptor. It is used to monitor multiple file descriptors for I/O readiness. Performance – O(1). Linux specific.
epoll_wait_old           | -            | x
eventfd                  | -            | x
eventfd2                 | -            | x
execve                | -           | x
execveat                 | -            | x
exit                     | P            | terminates only the calling process (or thread) and returns a status code to its parent
exit_group               | P            | terminates all the processes (or threads) in the same thread group as the calling process and returns a status code to their parent
faccessat             | -           | x
fadvise64                | -            | x
fallocate                | -            | x
fanotify_init            | -            | x
fanotify_mark         | -           | x
fchdir                   | -            | x
fchmod                   | -            | x
fchmodat                 | -            | x
fchown                | -           | x
fchownat                 | -            | x
fcntl                    | -            | x
fdatasync                | -            | x
fgetxattr             | -           | x
finit_module             | -            | x
flistxattr               | -            | x
flock                    | -            | x
fork                  | P           | Creates a new child process with a separate memory space from the parent process. Does not block the parent process while executing the child process
fremovexattr             | -            | x
fsetxattr                | -            | x
fstat                    | -            | x
fstatfs               | -           | x
fsync                    | -            | x
ftruncate                | -            | x
futex                    | C            | Implements basic locking or as a building block for higher-level locking abstractions. It is typically used as a blocking construct in the context of shared-memory synchronization.
futimesat             | -           | x
get_kernel_syms          | -            | x
get_mempolicy            | -            | x
get_robust_list          | -            | x
get_thread_area       | -           | x
getcpu                   | -            | x
getcwd                   | -            | x
getdents                 | -            | x
getdents64            | -           | x
getegid                  | -            | x
geteuid                  | -            | x
getgid                   | -            | x
getgroups             | -           | x
getitimer                | -            | x
getpeername              | -            | x
getpgid                  | -            | x
getpgrp               | -           | x
getpid                   | -            | x
getpmsg                  | -            | x
getppid                  | -            | x
getpriority           | -           | x
getrandom                | -            | x
getresgid                | -            | x
getresuid                | -            | x
getrlimit             | -           | x
getrusage                | -            | x
getsid                   | -            | x
getsockname              | -            | x
getsockopt            | -           | x
gettid                   | -            | x
gettimeofday             | -            | x
getuid                   | -            | x
getxattr              | -           | x
init_module              | -            | x
inotify_add_watch        | -            | x
inotify_init             | -            | x
inotify_init1         | -           | x
inotify_rm_watch         | -            | x
io_cancel                | -            | x
io_destroy               | -            | x
io_getevents          | -           | x
io_pgetevents            | -            | x
io_setup                 | -            | x
io_submit                | -            | x
ioctl                 | -           | x
ioperm                   | -            | x
iopl                     | -            | x
ioprio_get               | -            | x
ioprio_set            | -           | x
kcmp                     | -            | x
kexec_file_load          | -            | x
kexec_load               | -            | x
keyctl                | -           | x
kill                     | -            | x
lchown                   | -            | x
lgetxattr                | -            | x
link                  | -           | x
linkat                   | -            | x
listen                   | -            | x
listxattr                | -            | x
llistxattr            | -           | x
lookup_dcookie           | -            | x
lremovexattr             | -            | x
lseek                    | -            | x
lsetxattr             | -           | x
lstat                    | -            | x
madvise                  | -            | x
mbind                    | -            | x
membarrier            | -           | x
memfd_create             | -            | x
migrate_pages            | -            | x
mincore                  | -            | x
mkdir                 | -           | x
mkdirat                  | -            | x
mknod                    | -            | x
mknodat                  | -            | x
mlock                 | -           | x
mlock2                   | -            | x
mlockall                 | -            | x
mmap                     | -            | x
modify_ldt            | -           | x
mount                    | -            | x
move_pages               | -            | x
mprotect                 | -            | x
mq_getsetattr         | -           | x
mq_notify                | -            | x
mq_open                  | -            | x
mq_timedreceive          | -            | x
mq_timedsend          | -           | x
mq_unlink                | -            | x
mremap                   | -            | x
msgctl                   | -            | x
msgget                | -           | x
msgrcv                   | -            | x
msgsnd                   | -            | x
msync                    | -            | x
munlock               | -           | x
munlockall               | -            | x
munmap                   | -            | x
name_to_handle_at        | -            | x
nanosleep             | -           | x
newfstatat               | -            | x
nfsservctl               | -            | x
open                     | -            | x
open_by_handle_at     | -           | x
openat                   | -            | x
pause                    | -            | x
perf_event_open          | -            | x
personality           | -           | x
pipe                     | -            | x
pipe2                    | -            | x
pivot_root               | -            | x
pkey_alloc            | -           | x
pkey_free                | -            | x
pkey_mprotect            | -            | x
poll                     | C            | Monitors file descriptors for events and returns when some events are indicated or the timeout has occurred. It is similar to select (2) and epoll (2).
ppoll                 | C           | Monitors file descriptors for events and returns when some events are indicated or the timeout has occurred. File descriptors can represent sockets, pipes, message queues or other inter-process communication channels. Unlike poll, ppoll allows the caller to specify a signal mask that is applied while waiting for events.
prctl                    | -            | x
pread64                  | -            | x
preadv                   | -            | x
preadv2               | -           | x
prlimit64                | -            | x
process_vm_readv         | -            | x
process_vm_writev        | -            | x
pselect6              | -           | x
ptrace                   | -            | x
putpmsg                  | -            | x
pwrite64                 | -            | x
pwritev               | -           | x
pwritev2                 | -            | x
query_module             | -            | x
quotactl                 | -            | x
read                  | -           | x
readahead                | -            | x
readlink                 | -            | x
readlinkat               | -            | x
readv                 | -           | x
reboot                   | -            | x
recvfrom                 | C            | Used to receive messages from a socket, whether or not it is connection-oriented. 
recvmmsg                 | -            | x
recvmsg               | C           | Receives messages from a socket and captures the address from which the data was sent. It can be used on both connected and unconnected sockets.
remap_file_pages         | -            | x
removexattr              | -            | x
rename                   | -            | x
renameat              | -           | x
renameat2                | -            | x
request_key              | -            | x
restart_syscall          | -            | x
rmdir                 | -           | x
rseq                     | -            | x
rt_sigaction             | -            | x
rt_sigpending            | -            | x
rt_sigprocmask        | -           | x
rt_sigqueueinfo          | -            | x
rt_sigreturn             | -            | x
rt_sigsuspend            | -            | x
rt_sigtimedwait       | -           | x
rt_tgsigqueueinfo        | -            | x
sched_get_priority_max   | -            | x
sched_get_priority_min   | -            | x
sched_getaffinity     | -           | x
sched_getattr            | -            | x
sched_getparam           | -            | x
sched_getscheduler       | -            | x
sched_rr_get_interval | -           | x
sched_setaffinity        | -            | x
sched_setattr            | -            | x
sched_setparam           | -            | x
sched_setscheduler    | -           | x
sched_yield              | C            | Used by a process to voluntarily give up the CPU and let other processes run. It can help improve system responsiveness and avoid busy loops.
seccomp                  | -            | x
security                 | -            | x
select                | C           | Inables a program to monitor multiple file descriptors for readiness for I/O operations without blocking. Similar to poll (2) and epoll (2), but it has some disadvantages.
semctl                   | -            | x
semget                   | -            | x
semop                    | -            | x
semtimedop            | -           | x
sendfile                 | -            | x
sendmmsg                 | -            | x
sendmsg                  | -            | x
sendto                | C           | Send a message to another socket. It can be used for both connected and unconnected sockets.
set_mempolicy            | -            | x
set_robust_list          | -            | x
set_thread_area          | -            | x
set_tid_address       | -           | x
setdomainname            | -            | x
setfsgid                 | -            | x
setfsuid                 | -            | x
setgid                | -           | x
setgroups                | -            | x
sethostname              | -            | x
setitimer                | -            | x
setns                 | -           | x
setpgid                  | -            | x
setpriority              | -            | x
setregid                 | -            | x
setresgid             | -           | x
setresuid                | -            | x
setreuid                 | -            | x
setrlimit                | -            | x
setsid                | -           | x
setsockopt               | -            | x
settimeofday             | -            | x
setuid                   | -            | x
setxattr              | -           | x
shmat                    | -            | x
shmctl                   | -            | x
shmdt                    | -            | x
shmget                | -           | x
shutdown                 | -            | x
sigaltstack              | -            | x
signalfd                 | -            | x
signalfd4             | -           | x
socket                   | -            | x
socketpair               | -            | x
splice                   | -            | x
stat                  | -           | x
statfs                   | -            | x
statx                    | -            | x
swapoff                  | -            | x
swapon                | -           | x
symlink                  | -            | x
symlinkat                | -            | x
sync                     | -            | x
sync_file_range       | -           | x
syncfs                   | -            | x
sysfs                    | -            | x
sysinfo                  | -            | x
syslog                | -           | x
tee                      | -            | x
tgkill                   | -            | x
time                     | -            | x
timer_create          | -           | x
timer_delete             | -            | x
timer_getoverrun         | -            | x
timer_gettime            | -            | x
timer_settime         | -           | x
timerfd_create           | -            | x
timerfd_gettime          | -            | x
timerfd_settime          | -            | x
times                 | -           | x
tkill                    | -            | x
truncate                 | -            | x
tuxcall                  | -            | x
umask                 | -           | x
umount2                  | -            | x
uname                    | -            | x
unlink                   | -            | x
unlinkat              | -           | x
unshare                  | -            | x
uselib                   | -            | x
userfaultfd              | -            | x
ustat                 | -           | x
utime                    | -            | x
utimensat                | -            | x
utimes                   | -            | x
vfork                 | P           | Creates a new child process that shares the same memory space with the parent process. Blocks the parent process until the child process calls exit() or exec()
vhangup                  | -            | x
vmsplice                 | -            | x
vserver                  | -            | x
wait4                 | -           | x
waitid                   | -            | x
write                    | -            | x
writev                   | -            | x

</details>