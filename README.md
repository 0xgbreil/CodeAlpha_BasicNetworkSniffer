# Basic Network Sniffer

## Description

**Basic Network Sniffer** is a simple Python-based tool developed as part of the **CodeAlpha Cyber Security Internship**.

The project demonstrates the fundamentals of network packet capturing and analysis using the Scapy library. It is designed for educational purposes and focuses on understanding how network traffic flows through different protocols.

---

## Project Screenshots


![Startup](Images/1.png)

![TCP Packet](Images/2.png)

---

## Features

- Capture live network packets.
- Detect TCP, UDP, and ICMP packets.
- Display source and destination IP addresses.
- Display source and destination MAC addresses.
- Display source and destination ports.
- Identify the associated network service.
- Display packet size.
- Display packet payload (when available).
- Show the packet capture timestamp.
- Simple and readable colored terminal output.

---
## Installation

### Linux

```bash
git clone https://github.com/0xgbreil/CodeAlpha_BasicNetworkSniffer.git

cd CodeAlpha_BasicNetworkSniffer

pip3 install -r requirements.txt

sudo python3 sniffer.py
```

### Windows

```bash
git clone https://github.com/0xgbreil/CodeAlpha_BasicNetworkSniffer.git

cd CodeAlpha_BasicNetworkSniffer

pip install -r requirements.txt

python sniffer.py
```

> **Important:** Before running the tool on Windows, install **Npcap** with **WinPcap API-compatible Mode** enabled during installation. Also, run the terminal as **Administrator** to allow packet capturing.

### Windows Users

Before running the tool, download and install **Npcap**:

https://npcap.com/

During installation, make sure to enable:

- **Install Npcap in WinPcap API-compatible Mode**

Then run the terminal as **Administrator**.

## Usage

1. Run the program.
2. Select a network interface.
3. Start capturing packets.
4. Press **Ctrl + C** to stop the program.
## Future Improvements

This project is intentionally kept simple to satisfy the internship requirements.

A more advanced version of this tool will be developed in the future with additional features such as advanced packet filtering, logging, protocol statistics, file export, and other network analysis capabilities.

---


## Contact

**Mohamed Gbreil (0xgbreil)**

- LinkedIn: https://www.linkedin.com/in/0xgbreil/
- GitHub: https://github.com/0xgbreil
- X (Twitter): https://x.com/0xgbreil
  > **Note:** This project was developed and tested on Parrot OS Linux. It is also compatible with Windows after installing Npcap.
