# WannaCry Ransomware Analysis

![Analysis Type](https://img.shields.io/badge/Analysis-Static%20%26%20Dynamic-blue)
![Tools](https://img.shields.io/badge/Tools-FLARE%20VM%20%7C%20REMnux%20%7C%20PE%20Studio%20%7C%20Cutter%20%7C%20Wireshark%20%7C%20ProcMon-green)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-orange)

## 📌 Overview
This project provides a comprehensive analysis of the WannaCry ransomware sample using both static and dynamic analysis techniques. The objective is to understand how WannaCry functions, its propagation mechanism, and its impact on infected systems.

---

## 📁 Table of Contents
- [Analysis Environment](#analysis-environment)
- [Static Analysis](#static-analysis)
- [Dynamic Analysis](#dynamic-analysis)
- [Summary](#summary)
- [Installation & Usage](#installation--usage)
- [Disclaimer](#disclaimer)
- [Author](#author)

---

## 🔍 Analysis Environment
The analysis was conducted using isolated virtual machines to ensure safety during the process:

### FLARE VM (Windows Analysis)
- **Tools:** PE Studio, Floss, Capa, Cutter, Process Monitor (ProcMon)

### REMnux (Linux Analysis)
- **Tools:** INetSim, Wireshark

### Safety Precautions
- Both VMs were isolated from the internet and set to Host-only Network.
- Snapshots of both VMs were taken before starting the analysis.

---

## 📊 Static Analysis
### File Identification
- **File Name:** wannacry.exe
- **File Type:** Executable file
- **MD5 Hash:** db349b97c37d22f5ea1d1841e3c89eb4
- **SHA-1 Hash:** e889544aff85ffaf8b0d0da705105dee7c97fe26
- **SHA-256 Hash:** 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c

### Tools Used
- **PE Studio, Floss, Capa**
- Interesting API calls include:
  - `CryptGetRandom`
  - `CryptAcquireContextA`
  - `InternetOpenA`
  - `InternetOpenUrl`
  - `CreateServiceA`
  - `ChangeServiceConfig2A`

### Malware Capabilities
- Evades detection using anti-analysis techniques (stackstrings, timing checks, etc.).
- Establishes communication channels via HTTP and socket-based methods.
- Manipulates files and services for persistence and command execution.
- Uses TCP/UDP connections for network communication.
- Compresses and extracts data for exfiltration or payload management.
- Dynamically links functions to evade static analysis.

---

## 🧩 Dynamic Analysis
### Network-based Indicators
- **Tools Used:** Wireshark, InetSim, TCPView, ProcMon.
- **INetSim Configuration:** Activated to simulate network services.
- **Wireshark Capture:** Detected suspicious HTTP GET request for Command-and-Control (C2) communication.
- **Cutter Analysis:** Successful connection to C2 domain stops malware execution. INetSim must be turned off for full detonation.

![Wireshark Capture](images/wireshark_capture.png)

### Sample Execution (FLARE VM)
- **TCPView Analysis:** Failed TCP port 445 (SMB) connections indicate propagation attempts using EternalBlue exploit.

![TCPView Analysis](images/tcpview_analysis.png)

### Host-based Indicators
- **Process Monitor Observations:**
  - Creation of `taskhsvc.exe` in Windows C: drive.
  - Generation of randomly named directories in `C:\ProgramData`.
  - Persistent service registration (`tasksche.exe`).

![Process Monitor Observations](images/procmon_observations.png)

---

## ✅ Summary
The WannaCry ransomware sample encrypts files and propagates using the EternalBlue exploit. It employs anti-analysis techniques and persists by creating services and storing files in hidden directories. Network availability plays a critical role in its execution. Disabling INetSim during analysis allows the ransomware to fully deploy its payload.

---

## 📌 Installation & Usage
1. Clone the repository:
```bash
 git clone https://github.com/YourUsername/WannaCry-Ransomware-Analysis.git
```
2. Navigate to the directory:
```bash
 cd WannaCry-Ransomware-Analysis
```
3. Review the report and other files.

---

## ⚠️ Disclaimer
This analysis was conducted in a controlled, isolated environment. Attempting to run ransomware samples on a live or network-connected system can result in severe data loss and network damage. Proceed with caution.

---

## 👤 Author
Elliot Jonah

Feel free to add this to your portfolio and modify it as needed.
