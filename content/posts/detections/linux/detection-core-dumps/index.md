---
title: "Detect Core Dumps"
date: 2023-05-28T19:47:08+01:00
description: Detect core dumps on a Linux environment
menu:
  sidebar:
    name: Detect Core Dumps
    identifier: detect-core-dumps
    parent: linux
    weight: 10
hero: password-with-hand-holding-tweezers-binary-code.jpg
mermaid: true
tags: ["Threat Detection","Linux","Core Dumps"]
categories: ["security"]
---
## Core Dumps

> A core dump is a file containing a process's address space (memory) when the process terminates unexpectedly. Core dumps may be produced on-demand (such as by a debugger), or automatically upon termination. Core dumps are triggered by the kernel in response to program crashes, and may be passed to a helper program (such as systemd-coredump(8)) for further processing. <sup>[1]</sup>

As core dumps are a record of the process memory, a user or administrator that can force a core dump and has access to the resulting file and can potentially can potentially gain access to sensitive data, e.g secrets.

This threat can be eradicated if you disable core dumps. However, there are operational benefits from core dumps. Therefore you may be willing to favor the improved stability and troubleshooting it brings. If you decide to assume that risk and don't apply the mitigation strategy you should develop an approach to monitor this activity.

Instead of focusing on commands that can create a core dump consider the list of the signals which cause a process to dump core, e.g. SIGABRT. <sup>[2, 3]</sup> However, not all monitoring tools are fitted for this level of detail. As an alternative, you can consider /proc/[pid]/coredump_filter, which is used to "control which memory segments are written to the core dump file in the event that a core dump is performed".<sup>[2]</sup> Given that /proc/[pid]/coredump_filter needs to be opened to understand what is going to be written to the coredump, e.g. openat(AT_FDCWD, "/proc/1688715/coredump_filter", O_RDONLY|O_CLOEXEC) = 14, you can develop a file access monitoring strategy.

## Mitigation
* Disable core dumps <sup>[3, 4]</sup>

## Detection
### Auditd
```bash
# example of auditd rule for arm64 and /var/lib/systemd/coredump as the core dump default location
-a always,exit -F arch=b64 -S openat  -S renameat -S unlinkat -S renameat2 -S linkat -F perm=wa -F dir=/var/lib/systemd/coredump -k CORE_DUMP
```

<!-- ### Capsule8
```bash
Core dump:
  policy: fileaccess
  enabled: true
  alertMessage: Core dump
  comments: Identify whenever a core dump is created
  priority: Medium
  rules:
    - match operation == "open" and filePath in $Core-dump-on-restricted-machine-filePath-list
    - default ignore
Core-dump-on-restricted-machine-filePath-list:
  type: paths
  list:
  - "/var/lib/systemd/coredump/*"
  - "/proc/*/coredump_filter"
``` -->

### Falco
```yaml
- macro: open_read
  condition: (evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar='f' and fd.num>=0)

- rule: Core dump
  desc: >
    An attempt to read core dump.
  enabled: true
  condition: >
    evt.category=file 
    and open_read
    and (fd.name pmatch "/var/lib/systemd/coredump/" or fd.name glob "/proc/*/coredump_filter")
  output: |
    # Event information
    evt_rawres=%evt.rawres, evt_type=%evt.type, evt_dir=%evt.dir, syscall_type=%syscall.type, evt_category=%evt.category, evt_args=%evt.args, 
    # Process information
    proc_pid=%proc.pid, proc_exe=%proc.exe, proc_name=%proc.name, proc_args=%proc.args, proc_cmdline=%proc.cmdline, proc_exeline=%proc.exeline, proc_cwd=%proc.cwd, proc_nthreads=%proc.nthreads, proc_nchilds=%proc.nchilds, proc_ppid=%proc.ppid, proc_pname=%proc.pname, proc_pcmdline=%proc.pcmdline, proc_apid_2=%proc.apid[2], proc_aname_2=%proc.aname[2], proc_apid_3=%proc.apid[3], proc_aname_3=%proc.aname[3], proc_apid_4=%proc.apid[4], proc_aname_4=%proc.aname[4], proc_loginshellid=%proc.loginshellid, proc_duration=%proc.duration, proc_fdopencount=%proc.fdopencount, proc_vmsize=%proc.vmsize, proc_sid=%proc.sid, proc_sname=%proc.sname, proc_tty=%proc.tty, proc_exepath=%proc.exepath, proc_vpgid=%proc.vpgid, proc_is_exe_writable=%proc.is_exe_writable,
    # Threat information
    #thread_cap_permitted=%thread.cap_permitted, thread_cap_inheritable=%thread.cap_inheritable, thread_cap_effective=%thread.cap_effective,
    # File descriptor information
    fd_num=%fd.num, fd.type=%fd.type, fd_name=%fd.name, 
    # User and group information
    user_uid=%user.uid, user_name=%user.name, user_homedir=%user.homedir, user_shell=%user.shell, user_loginuid=%user.loginuid, user_loginname=%user.loginname, group_gid=%group.gid, group_name=%group.name
  priority: WARNING
  tags: [filesystem, mitre_credential_access, mitre_discovery]
```

## Validation
```bash
sleep 300 &
PID=$!
kill -s SIGSEGV "$PID"
```

## Bed Time Reading
1. https://wiki.archlinux.org/title/Core_dump
2. https://man7.org/linux/man-pages/man5/core.5.html
3. https://man7.org/linux/man-pages/man7/signal.7.html
4. https://linux-audit.com/understand-and-configure-core-dumps-work-on-linux/#disable-core-dumps