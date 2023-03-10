
## Performance Analysis

### Open5gs

**syscount: Syscalls and system processes analysis**

We start by analysis the syscall counts across the system and related process, as well as their latency information. This is very useful for general workload characterization.

```bash
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e user=ubuntu -e duration=20 -e aduration=35 -e interval=0 \
    -e syscount.py -x --d 2 -e tool=syscount -e ues=50
```
*futex*
The open5gs has a lot of futex system calls. Once one the reasons for high futex system calls on VM is high contention on shared-memory resources that causes many threads to wait on futexes <a href="https://access.redhat.com/solutions/534663">source</a>. Ran the analysis on open5gs system that is not receiving an traffic and we still got active or a lot of syscalls. To get a visibility of the processes producing the futex syscalls we ran `sudo python3 syscount.py --syscall futex -L -P -d 2`, this gave is the results below.

```
PID    COMM               COUNT        TIME (us)
589    mongod               116     11435520.245
829    open5gs-hssd          18      6001265.173
811    open5gs-pcrfd         18      6001076.447
613    rsyslogd              47      1503552.158
615    snapd                 49      1450911.342
460    multipathd             5      1000243.190
21077  [unknown]              1            4.092
21081  [unknown]              1            3.521
21078  [unknown]              1            3.101
21080  [unknown]              1            2.203
```

For a system not receiving traffic, this points the source of the futex system calls being high contention on shared-memory resources. To reduce this we will need to run the open5gs system on a larger instance.

- [ ] TODO: Verify source of high futex - compare performance of open5gs on different VM instances. Can also compare on hardware server.

*epoll_wait*

The system also has a large epoll_wait system calls when receiving traffic. The possible reasons for this are:

1. You have more file descriptors ready than the maxevents parameter you passed to epoll_wait, and the system call is round-robin through them1.
2. You have a signal handler that interrupts epoll_wait and causes it to return with an error code (EINTR). You may need to check for this error and retry the system call.
- To confirm this we ran `sudo python3 syscount.py -x --d 2` which gives a list of failed system calls. epoll_wait was not on the list. Also ran `sudo python3 syscount.py -e EINTR --d 2` to check for processes failing with the above error, of which none were failing.
3. You have a problem with timer handling or scheduling latency across system suspend or resume, which may trigger a watchdog logic that aborts epoll_wait https://github.com/systemd/systemd/issues/23032
