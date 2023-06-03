---
title: Unveiling the Secrets of Linux Core Dumps
date: 2023-05-28T19:47:08+01:00
# description: Unveiling the Secrets of Linux Core Dumps
menu:
  sidebar:
    name: Unveiling the Secrets of Linux Core Dumps
    identifier: detect-core-dumps
    parent: linux
    weight: 10
hero: password-with-hand-holding-tweezers-binary-code.jpg
mermaid: true
tags: ["Threat Detection","Linux","Core Dumps"]
categories: ["security"]
---
## Unveiling the Secrets of Linux Core Dumps

A Linux core dump, also known as a core dump file, is a file that captures the memory contents of a running process when it encounters a critical error or crashes. It is a snapshot of the process's memory at the time of the crash, including the values of variables, registers, and other relevant data. When a program crashes or terminates abnormally due to an error, the operating system generates a core dump file to help in debugging and understanding the cause of the crash. This file contains valuable information that can be analyzed to diagnose the issue and fix the software or identify vulnerabilities.

The core dump file is typically written to disk in a binary format but it can also be passed to a helper program (such as systemd-coredump(8)) for further processing. The memory image of the crashed process includes the program's code, stack frames, heap data, and other relevant information. By examining the core dump, developers and security professionals can gain insights into the state of the program at the time of the crash, helping them identify bugs, memory corruption issues, or security vulnerabilities.

To analyze a core dump file, various debugging tools and techniques can be used. These tools allow the examination of memory regions, registers, and stack frames to understand the flow of the program before it crashed. Debuggers like GDB (GNU Debugger) are commonly used to load the core dump file and perform detailed analysis, including inspecting variables, stepping through the code, and examining memory regions.

Security detection engineers may utilize core dumps as part of their investigations when analyzing incidents related to software crashes, exploits, or malicious activities. By examining the core dump, they can gather crucial information about the exploit or identify potential vulnerabilities that were exploited.

It's worth noting that core dumps may contain sensitive information, such as passwords or encryption keys, depending on the state of the crashed process. Therefore, it's important to handle core dump files with care, restrict access to authorized personnel, and ensure they are securely stored to prevent unauthorized access to sensitive data.

## Threat Actor Exploitation of Core Dumps

In general, a core dump file itself does not pose a direct risk when it comes to threat actors using it maliciously. However, threat actors can potentially leverage the information contained within a core dump to aid in their attacks or exploit vulnerabilities. Here are a few scenarios where a threat actor might find value in a core dump:

1. Information Disclosure: If the core dump file contains sensitive information, such as passwords, API keys, or cryptographic keys, a threat actor could analyze the dump to extract and exploit that data.

2. Exploit Analysis: By examining a core dump, threat actors can gain insights into the inner workings of a crashed process. They can analyze the memory contents to identify vulnerabilities, memory corruption issues, or other weaknesses that could be exploited for their malicious activities.

3. Reverse Engineering: A threat actor may use a core dump file to reverse engineer the software and understand its internal structure, algorithms, or proprietary protocols. This knowledge can be leveraged to craft more sophisticated attacks or develop exploits targeting specific vulnerabilities.

4. Debugging Exploits: Core dumps provide detailed information about the state of a crashed process, including register values, stack traces, and memory contents. Threat actors can use this information to debug their exploits, fine-tune their attack techniques, or identify potential weaknesses to bypass security measures.

## Threat Actor Techniques: How They Force Core Dumps

In the realm of cybersecurity, threat actors continuously devise new methods to achieve their malicious objectives. One technique they may employ is to force a core dump on a targeted system. In this section, we will explore how threat actors can force core dumps and the potential risks associated with these actions.

**Method 1: Exploiting Vulnerabilities**
One common approach utilized by threat actors involves exploiting software vulnerabilities. By identifying weaknesses in applications or the underlying operating system, they can trigger crashes or abnormal terminations intentionally. Vulnerabilities such as memory corruption, buffer overflow, or programming errors may serve as entry points. Through targeted exploitation, threat actors can force a process to crash, ultimately leading to the generation of a core dump.

**Method 2: Resource Exhaustion**
Another technique is to exhaust system resources deliberately. By overwhelming a specific process or the system as a whole, threat actors can cause a crash scenario. Excessive consumption of memory, CPU, or other critical resources can result in an abnormal termination, triggering the creation of a core dump.

**Method 3: Signal Injection**
Threat actors may manipulate vulnerable applications to generate specific signals, such as the `SIGSEGV` (segmentation fault) signal. This signal, when injected, causes a process to terminate abruptly. By exploiting the application's vulnerability to signal injection, threat actors can induce a crash scenario and prompt the system to generate a core dump.

**Method 4: Debugging Tools Abuse**
If a threat actor gains unauthorized access to a system or compromises a privileged account, they may abuse debugging tools that allow core dump generation. Debuggers like GDB (GNU Debugger) or similar utilities can be misused to force crashes, intercept signals, or manipulate the target process's behavior. Through such manipulation, threat actors can trigger core dump creation.

## Mitigation Strategies

To effectively eradicate the threat associated with core dump files falling into the wrong hands, it is important to implement a combination of preventive measures and incident response practices. Here are some steps you can take:

1. Access Controls: Implement strong access controls to restrict access to core dump files. Only authorized personnel should have permission to access and analyze these files. Regularly review and update access privileges to ensure they align with the principle of least privilege.

2. Secure Storage and Encryption: Store core dump files in a secure location, such as a dedicated and protected directory or server, with proper encryption in place. Encryption adds an extra layer of protection, especially if the files are stored or transferred over untrusted networks.

3. Data Sanitization: Before sharing or analyzing core dump files, ensure sensitive data within the dumps, such as passwords, keys, or personally identifiable information (PII), is removed or obfuscated. This can be achieved by scrubbing or sanitizing the dumps using appropriate tools or techniques.

4. Incident Response Planning: Develop a comprehensive incident response plan specifically tailored to address incidents involving core dump files. This plan should outline the steps to be taken when a core dump is compromised or potentially accessed by unauthorized parties.

5. Monitoring and Detection: Implement robust monitoring and detection mechanisms to identify any unauthorized access attempts or suspicious activities related to core dump files. This can include intrusion detection systems, log analysis, and security event monitoring.

6. Regular Auditing and Review: Conduct regular audits and reviews of the access logs, storage locations, and security measures related to core dump files. This helps ensure that security controls are functioning as intended and any vulnerabilities or misconfigurations are promptly addressed.

7. Employee Awareness and Training: Provide training and awareness programs to employees involved in handling core dump files. Educate them about the importance of securing and handling these files properly, including the risks associated with their exposure and the best practices to mitigate those risks.

## Threat Detection Rules

Rather than emphasizing commands that generate core dumps, shift your focus to what can create a core dump, e.g. consider the list of signals that trigger core dump creation in a process, e.g. SIGABRT. <sup>[2, 3]</sup>. However, not all monitoring tools are equipped to handle such intricate levels of detail. As an alternative, you can take advantage of /proc/self/coredump_filter. The /proc/self/coredump_filter file is used in Linux systems to control the types of information that are included in a core dump file when a process crashes. It allows a process to specify which memory segments and resources should be included or excluded from the core dump. Before generating the core dump, the operating system checks the settings in the /proc/self/coredump_filter file to determine which memory segments and resources should be included in the core dump, e.g. openat(AT_FDCWD, "/proc/1688715/coredump_filter", O_RDONLY|O_CLOEXEC) = 14. The operating system reads the bitmask specified in the file to understand the process's preferences for the contents of the core dump. Based on the settings in the coredump_filter file, the operating system includes or excludes the corresponding memory segments and resources when creating the core dump file.

### Auditd
To detect when a process reads its own core dump filter settings, we will leverage the power of auditd, the Linux auditing framework. Follow these steps to create the FIM rule:
1. Open the audit rules configuration file using a text editor:
```bash
sudo vim /etc/audit/rules.d/audit.rules
```

2. Add the following line to the file:
```bash
-w /proc/self/coredump_filter -p r -k coredump_filter_read
```
This rule instructs auditd to monitor the file /proc/self/coredump_filter for read operations (-p r). When a process reads this file, an audit event will be generated and labeled with the key coredump_filter_read (-k coredump_filter_read).

3. Save the file and exit the text editor.

4. Restart the auditd service to apply the changes:
```bash
sudo service auditd restart
```

### Falco
Falco is a powerful open-source cloud-native runtime security tool that enables real-time threat detection and response. Here's an example of a Falco rule that can detect when a process reads the /proc/self/coredump_filter file:

1. Open the falco rules configuration file using a text editor:
```bash
sudo nano /etc/falco/falco_rules.local.yaml
```

2. Add the following macro and rule to the file: 
```yaml
- macro: open_read
  condition: (evt.type in (open,openat,openat2) and evt.is_open_read=true and fd.typechar='f' and fd.num>=0)

- rule: Core dump file created
  desc: >
    Identifies attempts to create a core dump file.
  enabled: true
  condition: >
    evt.category=file 
    and open_read
    and fd.name = "/proc/self/coredump_filter"
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

3. Save the file and exit the text editor.

4. Restart the falco service to apply the changes:
```bash
sudo service falco restart
```

> **Note**
> Make sure to configure Falco properly to ensure it captures the necessary system events and performs the desired detection. Adjust the rule according to your specific environment and monitoring needs.

## Validation
Once you have implemented a FIM rule to detect process access to the /proc/self/coredump_filter file, it is essential to verify that the detection logic is functioning correctly. In this section, we will walk you through the steps to test the detection logic of the rule and ensure that it generates the expected output when a process reads the core dump filter file. Regularly testing and validating your security monitoring rules is crucial to ensure that your system remains protected against unauthorized or suspicious activities.


**Step 1: Preparing the Environment**
Before testing the rule, ensure that you have Falco or auditd properly installed and running on your system. Refer to the tool documentation for guidance on installation and configuration specific to your environment.

**Step 2: Performing the Test**
To test the detection logic, execute the following commands:
```bash
sleep 300 &
PID=$!
kill -s SIGSEGV "$PID"
```

**Step 3: Analyze Results**
Analyze the output generated by the detection logic and compare it against the expected results for the test scenario. Determine whether the detection logic accurately detects the simulated threat and creates and audit record and provides an appropriate alert.

## Bed Time Reading
1. https://wiki.archlinux.org/title/Core_dump
2. https://man7.org/linux/man-pages/man5/core.5.html
3. https://man7.org/linux/man-pages/man7/signal.7.html
4. https://linux-audit.com/understand-and-configure-core-dumps-work-on-linux/#disable-core-dumps