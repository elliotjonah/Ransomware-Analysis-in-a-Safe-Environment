# WannaCry Ransomware Analysis Report

**Analyst:** Elliot Jonah  
**Date:** [Date of Analysis]

---

## 📌 Introduction
In the early summer of 2017, WannaCry was unleashed on the world. Widely considered to be one of the most devastating malware infections to date, WannaCry left a trail of destruction in its wake. It is a classic ransomware cryptoworm, meaning it can encrypt individual hosts and propagate through a network on its own.  

This report provides a comprehensive analysis of the WannaCry ransomware sample using both static and dynamic analysis techniques. The objective is to understand how WannaCry functions, its propagation mechanism, and its impact on infected systems. The analysis was performed on isolated virtual machines: **FLARE VM (Windows-based)** and **REMnux (Linux-based)**.

---

## 🔧 Environment Setup
### FLARE VM (Windows Analysis)
- **Tools:** PE Studio, Floss, Capa, Cutter, Process Monitor (ProcMon).

### REMnux (Linux Analysis)
- **Tools:** INetSim, Wireshark.

### Safety Precautions
- Both VMs are isolated from the internet and set to **Host-only Network**.
- Snapshots of both VMs were taken before starting the analysis.

---

## 📂 Static Analysis (FLARE VM)
### 3.a VirusTotal Scan
- **70/72 vendors flagged the file as malicious.**

### 3.b File Identification
- **File Name:** wannacry.exe  
- **File Type:** [Executable file]  
- **MD5 Hash:** db349b97c37d22f5ea1d1841e3c89eb4  
- **SHA-1 Hash:** e889544aff85ffaf8b0d0da705105dee7c97fe26  
- **SHA-256 Hash:** 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c

### 3.c Strings Analysis (Tools: PE Studio, Floss, Capa)
- **Interesting API Calls:**  
  - CryptGetRandom  
  - CryptAcquireContextA  
  - InternetOpenA  
  - InternetOpenUrl  
  - CreateServiceA  
  - ChangeServiceConfig2A

- **Capa Output:**  
  - The malware attempts to hide itself, gather information, execute malicious code, and maintain persistence.  
  - It installs additional tools and terminates processes/threads as part of its malicious activities.

**Capa Analysis Screenshot:**  
![Capa Analysis](./images/capa_analysis.png)

---

## 📊 Dynamic Analysis
### 4.1 Network-Based Indicators (REMnux)
- **Tools Used:** Wireshark, INetSim, TCPView, Process Monitor (ProcMon)
- **Network Simulation Setup (INetSim):** INetSim is turned on and confirmed to be running.

**Wireshark Capture Screenshot:**  
![Wireshark Capture](./images/wireshark_capture.png)

### 4.2 Sample Execution (FLARE VM)
- **Tools Used:** TCPView, ProcMon
- The infected machine (10.0.0.5) attempts multiple **TCP connections on port 445 (SMB)**, indicating propagation attempts via the **EternalBlue vulnerability**.

**TCPView Screenshot:**  
![TCPView Analysis](./images/tcpview_analysis.png)

---

## 📝 Host-Based Indicators (FLARE VM)
### Process Monitor Observations
- Filtering for `wannacry` processes and monitoring **file operations**.
- Creation of the file: `taskhsvc.exe` in the `C:\` drive.
- Another executable with a strange name in the `C:\ProgramData` directory.
- The directory `hxqfjqteswoy300` is a randomly generated folder used by the malware to store its executables, encryption keys, and encrypted files.
- A suspicious folder named `bgyurhsfe952` is found, which is likely created to store files and register itself as a service for persistence.

**Process Monitor Screenshot:**  
![Process Monitor Analysis](./images/procmon_analysis.png)

---

## 🔐 Summary of Findings
- WannaCry is designed to:
  - **Evade detection** using anti-analysis techniques (stackstrings, timing checks, etc.).
  - **Establish communication channels** using both HTTP and socket-based methods.
  - **Manipulate files and services** to achieve persistence and execute commands.
  - **Perform network communication** using TCP/UDP connections.
  - **Compress and extract data**, likely for exfiltration or payload management.
  - **Dynamically link functions**, making static analysis more challenging.

---

## 📚 References
- [Capa Documentation](https://github.com/mandiant/capa)
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Process Monitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon)

---

