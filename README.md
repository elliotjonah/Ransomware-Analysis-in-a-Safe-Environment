# Ransomware-Analysis-in-a-Safe-Environment
# WannaCry Ransomware Analysis

This report provides a detailed analysis of the WannaCry ransomware using both FLARE VM and REMnux. The focus of the analysis includes basic dynamic analysis, file behavior monitoring, and network traffic observation.

## Tools Used
- FLARE VM
- REMnux
- Wireshark
- Process Monitor
- FakeNet-NG

## Ransomware Sample
The ransomware sample used in this analysis is WannaCry. All tests were conducted in a safe, isolated environment to prevent unintended damage.

---

## Static Analysis

### File Information
- **File Name:** wannacry.exe
- **File Size:** 3.5 MB
- **File Type:** PE32 executable (GUI) Intel 80386, for MS Windows

### Strings Analysis
- Revealed strings suggesting network communication and file encryption activities.
- Notable strings: `.wnry`, `tor`, `decryptor`.

---

## Dynamic Analysis

### Environment Setup
- The ransomware sample was executed within a Windows 7 VM equipped with FLARE VM and network monitoring tools.
- REMnux was used for deeper network analysis.

---

## Behavioral Analysis

### Process Monitor Analysis
![Process Monitor Analysis](images/Screenshot%202025-03-14%20004836.png)
- Process Monitor revealed file modification activities targeting various files with `.wnry` extension.
- High CPU usage noted due to encryption processes.

### FakeNet-NG Analysis
![FakeNet-NG Analysis](images/Screenshot%202025-03-14%20004852.png)
- FakeNet-NG intercepted DNS queries and HTTP requests attempting to reach a specific kill-switch URL.
- This URL was hardcoded in the malware to terminate its execution if reachable.

### Network Traffic Analysis with Wireshark
![Wireshark Analysis](images/Screenshot%202025-03-14%20005136.png)
- Wireshark captured attempts to communicate with remote servers via TCP.
- Network packets showed encrypted communication consistent with ransomware behavior.

---

## Encryption Analysis

### Encrypted Files
![Encrypted Files](images/Screenshot%202025-03-14%20021709.png)
- Multiple files were encrypted and appended with the `.wnry` extension.
- A ransom note was dropped in affected directories.

---

## Ransom Note
![Ransom Note](images/Screenshot%202025-03-14%20021725.png)
- The ransom note demanded payment in Bitcoin to decrypt the files.
- It also provided instructions for victims to pay and recover files.

---

## Conclusion
The analysis confirms that the sample is WannaCry ransomware. It spreads via SMB vulnerability (MS17-010) and encrypts user files, demanding a ransom for decryption. The malware is programmed to cease operations if it can successfully reach a specific URL acting as a kill-switch.

Mitigation steps include:
- Ensuring systems are patched with MS17-010.
- Maintaining offline backups.
- Using intrusion detection systems to identify suspicious network activity.

---

## References
- [WannaCry Ransomware](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack)

---
