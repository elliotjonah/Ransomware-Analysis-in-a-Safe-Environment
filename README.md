# WannaCry Ransomware Analysis Report

**Analyst:** Elliot Jonah  
**Date:** [15th March, 2025]

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

<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/adb13e9cfaba8a3fc53b82b770a4f5afd921a68d/Screenshot%202025-03-13%20131536.png>
This was the observed symptoms of infection upon initial detonation. After use a snapshot to revert the VM to a clean state.

---

## 📂 Static Analysis (FLARE VM)
### 3.a VirusTotal Scan
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/adb13e9cfaba8a3fc53b82b770a4f5afd921a68d/Screenshot%202025-03-13%20170616.png>
- **70/72 vendors flagged the file as malicious.**

### 3.b File Identification
- **File Name:** wannacry.exe  
- **File Type:** [Executable file]  
- **MD5 Hash:** db349b97c37d22f5ea1d1841e3c89eb4  
- **SHA-1 Hash:** e889544aff85ffaf8b0d0da705105dee7c97fe26  
- **SHA-256 Hash:** 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c

### 3.c Strings Analysis (Tools: PE Studio, Floss, Capa)

<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20004626.png>
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20004836.png>
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20004852.png >

- **Interesting API Calls:**  
  - CryptGetRandom  
  - CryptAcquireContextA  
  - InternetOpenA  
  - InternetOpenUrl  
  - CreateServiceA  
  - ChangeServiceConfig2A

- **Capa Output:**
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20001758.png>
The malware attempts to hide itself, gather information, execute malicious code, and maintain persistence.


---
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20001845.png>
It installs additional tools and terminates processes/threads as part of its malicious activities.
 

---

## 📊 Dynamic Analysis
### 4.1 Network-Based Indicators (REMnux)
- **Tools Used:** Wireshark, INetSim, TCPView, Process Monitor (ProcMon)
- **Network Simulation Setup (INetSim):** INetSim is turned on and confirmed to be running.
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20123126.png>

**Wireshark Capture Screenshot:**  
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-18%20173538.png>
The Wireshark capture shows an HTTP GET request from 10.0.0.3 to a suspicious-looking URL (www.iuserfodgjfjasopdfjhgosurjjfsawehrwerqwea.com) hosted on 10.0.0.4, which resembles randomly generated domain names often used by malware for Command-and-Control (C2) communication.
After this event it seems like the malware does not execute or do anything. So we have to find out why the malware is not executing. We use a tool called Cutter for this investigation.

### 4.2 Sample Execution (FLARE VM)
- **Tools Used:** Cutter, TCPView, ProcMon
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20122231.png>
The code shows that the malware attempts to establish a connection to http://www.iuserfodgjfjasopdfjhgosurjjfsawehrwerqwea.com using the Windows API functions: InternetOpenA and InternetOpenUrlA. If the contact established the malware does not execute.
What this means is that to detonate the malware successfully, inetsim must be turned off.



---
**TCPView Screenshot:** 
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20021709.png>
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20021725.png>
- The infected machine (10.0.0.5) attempts multiple **TCP connections on port 445 (SMB)**, indicating propagation attempts via the **EternalBlue vulnerability**.


---

## 📝 Host-Based Indicators (FLARE VM)
### Process Monitor Observations
- Filtering for `wannacry` processes and monitoring **file operations**.
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-18%20183941.png>
- Creation of the file: `taskhsvc.exe` in the `C:\` drive.
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20024925.png>
- Another executable with a strange name in the `C:\ProgramData` directory.
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20030127.png>
- The directory `hxqfjqteswoy300` is a randomly generated folder used by the malware to store its executables, encryption keys, and encrypted files.
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-14%20025946.png>
- A suspicious folder named `bgyurhsfe952` is found, which is likely created to store files and register itself as a service for persistence.
<img src = https://github.com/elliotjonah/Ransomware-Analysis-in-a-Safe-Environment/blob/b98aca996f40e3021134c257a58a72ba4e560a1b/Screenshot%202025-03-18%20191420.png>


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

