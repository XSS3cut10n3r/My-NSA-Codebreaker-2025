# Task 3 - Digging deeper - (Reverse Engineering)

> The network administrators confirm that the IP address you provided in your description is an edge router. DAFIN-SOC is asking you to dive deeper and reverse engineer this device. Fortunately, their team managed to pull a memory dump of the device.

> Scour the device's memory dump and identify anomalous or malicious activity to find out what's going on.

> Your submission will be a list of IPs and domains, one per line. For example:
- `127.0.0.1 localhost`
- `192.168.54.131 corp.internal`
- `...`

---

## Downloads

- **Memory Dump** (`memory.dump.gz`)
- **Metadata** (`System.map.br`)
- **Kernel Image** (`vmlinux.xz`)

---

## Task

- **Submit a complete list of affected IPs and FQDNs, one per line.**

---

## Writeup

A reverse engineering task where we're given a memory dump, the kernel symbol map, and the kernel image. The first step is to discover the malicious binary and the second step is to reverse engineer it. To start with, I set up volatility and the kernel images. 



<p align="center">
<img src="images/badge3.png" alt="Badge" width="300"/>
</p>

**Success!** Three down, four to go.