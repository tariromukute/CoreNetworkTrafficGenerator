
## Performance Analysis

### Open5gs

**syscount: Syscalls and system processes analysis**

We start by analysis the syscall counts across the system and related process, as well as their latency information. This is very useful for general workload characterization.

We first ran syscalls analysis for an idle system, not receiving any traffic.

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -m -j", tool: syscount, ues: 0 }'
```

![Syscalls across the idle system (by latency)](./assets/syscount_fig_m2.medium_ue_0.jpeg "Syscalls across the idle system (by latency)")
<b>Fig.1 - Syscalls across the idle system (by latency)</b>

We then looked at the processes making these system calls on the idle system.

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -P -m -j", tool: sysprocess, ues: 0 }'
```

![Processes making syscall on idle system (by latency)](./assets/sysprocess_fig_m2.medium_ue_0..jpeg "Processes making syscall on idle system (by latency)")
<b>Fig.2 - Processes making syscall on idle system (by latency)</b>



**futex**

The open5gs has a lot of futex system calls. Once one the reasons for high futex system calls on VM is high contention on shared-memory resources that causes many threads to wait on futexes <a href="https://access.redhat.com/solutions/534663">source</a>. Therefore a lot of futex system calls on a VM may indicate that there is a lot of concurrent access to shared resources or data structures by multiple threads or processes. Ran the analysis on open5gs system that is not receiving an traffic and we still got active or a lot of syscalls. To get a visibility of the processes producing the futex syscalls we ran `sudo python3 syscount.py --syscall futex -L -P -d 2`, this gave is the results below.

<details><summary><b>Click to see results for processes making futex system calls</b></summary>

![Processes making futex syscall on idle system (by latency)](./assets/sysprocess_fig_m2.medium_ue_0..jpeg "Processes making futex syscall on idle system (by latency)")
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
</details>

**recvmsg**

The recvmsg system call is used to receive messages from a socket, and may be used to receive data on a socket. The syscall is used whether or not it is connection-oriented.

<details><summary><b>Click to see results for processes making recvmsg system calls</b></summary>

![Processes making recvmsg syscall on idle system (by latency)](./assets/sysprocess_recvmsg_fig_m2.medium_ue_0.jpeg "Processes making recvmsg syscall on idle system (by latency)")
<b>Fig.3.1 - Processes making recvmsg syscall on idle system (by latency)</b>

```json
{'time': '09:10:14', 'pid': 593, 'comm': 'mongod', 'count': 6, 'time (ms)': 19999.538979}
{'time': '09:10:14', 'pid': 7457, 'comm': 'open5gs-smfd', 'count': 192, 'time (ms)': 19970.266316}
{'time': '09:10:14', 'pid': 7456, 'comm': 'open5gs-pcrfd', 'count': 192, 'time (ms)': 19970.233162}
{'time': '09:10:14', 'pid': 7446, 'comm': 'open5gs-hssd', 'count': 191, 'time (ms)': 19866.473529}
{'time': '09:10:14', 'pid': 7441, 'comm': 'open5gs-mmed', 'count': 191, 'time (ms)': 19862.452266}
{'time': '09:10:14', 'pid': 332, 'comm': 'systemd-journal', 'count': 6, 'time (ms)': 0.073383}
{'time': '09:10:14', 'pid': 619, 'comm': 'rsyslogd', 'count': 8, 'time (ms)': 0.057932}
{'time': '09:10:14', 'pid': 540, 'comm': 'systemd-network', 'count': 6, 'time (ms)': 0.033791}
{'time': '09:10:14', 'pid': 7416, 'comm': 'open5gs-amfd', 'count': 2, 'time (ms)': 0.025493}
{'time': '09:10:14', 'pid': 1, 'comm': 'systemd', 'count': 1, 'time (ms)': 0.008691}
```

Get tracepoints for recvmsg `sudo python3 tplist.py | grep recvmsg`

Get arguments for recvmsg tracepoints:
* `sudo python3 tplist.py -v syscalls:sys_enter_recvmsg`
* `sudo python3 tplist.py -v syscalls:sys_exit_recvmsg`
</details>

**clock_nanosleep**

clock_nanosleep system calls are functions that allow a thread to sleep for a specified time interval with nanosecond precision <a href="https://man.archlinux.org/man/clock_nanosleep.2.en">source</a>. clock_nanosleep are mainly used by processes to manage their resources and avoid blocking other threads or processes. We see that the main processes using clock_nanosleep are `mongod` and `multipathd`.

`mongod` is a process that runs MongoDB, a cross-platform document-oriented database system and `multipathd` is a daemon that monitors and manages multipath devices on Linux systems. Multipath devices are virtual devices that combine multiple physical connections between a server and a storage array into one logical device

<details><summary><b>Click to see results for processes making clock_nanosleep system calls</b></summary>

Results
```json
{'time': '09:16:09', 'pid': 593, 'comm': 'mongod', 'count': 202, 'time (ms)': 35824.511271}
{'time': '09:16:09', 'pid': 459, 'comm': 'multipathd', 'count': 19, 'time (ms)': 19001.301196}

```
</details>

**poll**

<details><summary><b>Click to see results for processes making poll system calls</b></summary>

Results
```json
{'time': '09:16:09', 'pid': 593, 'comm': 'mongod', 'count': 202, 'time (ms)': 35824.511271}
{'time': '09:16:09', 'pid': 459, 'comm': 'multipathd', 'count': 19, 'time (ms)': 19001.301196}

```
</details>

**select**

<details><summary><b>Click to see results for processes making select system calls</b></summary>

Results
```json
{'time': '09:35:58', 'pid': 9770, 'comm': 'python3', 'count': 1, 'time (ms)': 20015.606103}
{'time': '09:35:58', 'pid': 9764, 'comm': 'python3', 'count': 3, 'time (ms)': 15011.22589}

```
</details>

**ppoll**

<details><summary><b>Click to see results for processes making ppoll system calls</b></summary>

Results
```json
{'time': '09:40:08', 'pid': 459, 'comm': 'multipathd', 'count': 3, 'time (ms)': 15000.181066}
```
</details>

**read**

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

<details><summary><b>Click to see results for processes making sendto system calls</b></summary>

Results
```json
{'time': '09:52:42', 'pid': 11919, 'comm': 'open5gs-scpd', 'count': 52, 'time (ms)': 1.148783}
{'time': '09:52:42', 'pid': 11964, 'comm': 'open5gs-nrfd', 'count': 18, 'time (ms)': 0.377699}
{'time': '09:52:42', 'pid': 11941, 'comm': 'open5gs-smfd', 'count': 6, 'time (ms)': 0.150069}
{'time': '09:52:42', 'pid': 12274, 'comm': 'python3', 'count': 4, 'time (ms)': 0.119476}
{'time': '09:52:42', 'pid': 11910, 'comm': 'open5gs-pcfd', 'count': 4, 'time (ms)': 0.119205}
{'time': '09:52:42', 'pid': 11916, 'comm': 'open5gs-bsfd', 'count': 4, 'time (ms)': 0.097661}
{'time': '09:52:42', 'pid': 11897, 'comm': 'open5gs-amfd', 'count': 4, 'time (ms)': 0.094302}
{'time': '09:52:42', 'pid': 11911, 'comm': 'open5gs-sgwcd', 'count': 4, 'time (ms)': 0.092473}
{'time': '09:52:42', 'pid': 11920, 'comm': 'open5gs-udmd', 'count': 4, 'time (ms)': 0.092105}
{'time': '09:52:42', 'pid': 11917, 'comm': 'open5gs-nssfd', 'count': 4, 'time (ms)': 0.07576}
```
</details>