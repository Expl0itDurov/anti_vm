# Virtual Machine Detection Techniques in Rust

This repository contains **technical and educational Rust code** demonstrating multiple **low-level techniques for detecting execution inside virtualized environments**. The implementation focuses on CPU behavior, system artifacts, and heuristic aggregation commonly studied in malware analysis, sandbox detection, and defensive security research.

This project is intended **strictly for academic, research, and defensive security purposes**.

---

## Technical Overview

Virtualization introduces observable side effects at different layers of the system stack. This project demonstrates how these artifacts can be detected by combining **CPU instruction timing**, **CPUID behavior**, and **operating system metadata analysis**.

The detection logic is heuristic-based and intentionally layered to reduce false negatives.

---

## Implemented Detection Methods

### 1. CPUID Instruction Timing Analysis (RDTSC)

The code measures the execution cost of the `CPUID` instruction using the `RDTSC` timestamp counter.

- `RDTSC` is read before and after executing `CPUID`
- Multiple samples are collected
- Low and high outliers are discarded
- An average cycle count is calculated

Virtual machines typically introduce additional overhead due to VM-exits, causing elevated cycle counts.

Detection condition:
- Average CPUID latency greater than a predefined threshold

This technique is widely referenced in **anti-analysis and sandbox detection literature**.

---

### 2. Hypervisor CPUID Leaf Detection

The implementation queries CPUID leaf `0x40000000`, which is reserved for hypervisors.

The returned register values are compared against known hypervisor signatures. The presence of a valid signature strongly indicates execution inside a virtual machine.

This method targets:
- VMware
- Hyper-V
- Other CPUID-compliant hypervisors

---

### 3. Invalid CPUID Leaf Behavior

The code executes `CPUID` with an intentionally invalid leaf (`0xFFFFFFFF`).

- Real hardware and hypervisors often respond differently
- Some virtual environments incorrectly echo the input value

The returned result is evaluated as a heuristic signal for virtualization.

---

### 4. System Metadata Keyword Analysis

Using the `sysinfo` crate, the program inspects:

- Hostname
- Operating system version
- Disk device names

These values are checked against a list of known virtualization-related keywords, including:
- vmware
- vbox
- qemu
- hyper-v
- xen
- kvm
- parallels

The presence of any keyword is treated as a virtualization indicator.

---

### 5. MAC Address Vendor Prefix Detection

The tool retrieves the system MAC address and checks for Organizationally Unique Identifiers (OUIs) associated with virtual machine vendors.

Known prefixes include:
- VMware
- VirtualBox
- Hyper-V

MAC-based detection remains a common and reliable heuristic in sandbox environments.

---

### 6. Virtualization-Specific File Detection (Windows)

The implementation checks for the presence of known virtualization-related driver files, such as:
- `vmmouse.sys`
- `vmhgfs.sys`
- `VBoxMouse.sys`

These files are typically present only inside guest operating systems.

---

## Heuristic Aggregation Strategy

All detection techniques are combined using logical OR conditions. If any detection method reports a positive result, the program immediately terminates execution.

This multi-signal approach increases detection reliability by compensating for weaknesses in individual heuristics.

---

## Limitations

- No VM detection technique is fully reliable in isolation
- Modern hypervisors actively attempt to hide artifacts
- False positives and false negatives are possible
- Results depend on system configuration and hypervisor behavior

This code is intended for **study and experimentation**, not as a definitive detection mechanism.

---

## Ethical and Legal Notice

This project is provided **for educational, academic, and defensive security research purposes only**.

- The author does not endorse malware development or malicious use
- Do not use this code to bypass security systems or evade lawful analysis
- Always comply with local laws and ethical research standards

---

## Learning Outcomes

By studying this repository, readers will gain insight into:
- CPU-level virtualization side effects
- Timing-based detection mechanisms
- CPUID behavior under virtualization
- Heuristic-based environment detection design
- The limitations of VM detection in modern systems
