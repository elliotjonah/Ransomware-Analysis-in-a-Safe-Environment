# Ransomware-Analysis-in-a-Safe-Environment
# WannaCry Ransomware Analysis

## Overview
This report details the process of analyzing the WannaCry ransomware using FLARE VM and REMnux. The goal of this analysis is to perform static and dynamic analysis to understand the malware's behavior, functionality, and potential indicators of compromise (IOCs).

## Tools Used
- **FLARE VM** (Windows-based malware analysis platform)
- **REMnux** (Linux-based malware analysis platform for reverse-engineering and malware research)
- **PEStudio** (Static analysis tool)
- **Process Monitor (ProcMon)** (Dynamic analysis tool)
- **Wireshark** (Network traffic analysis)

## Objectives
- Perform static analysis to gather information about the ransomware binary.
- Perform dynamic analysis to observe the malware's behavior during execution.
- Identify network-based Indicators of Compromise (IOCs).

## Static Analysis
### PEStudio Analysis
Using PEStudio on FLARE VM, the binary was loaded to inspect its properties. The tool provided insights into:
- **Imports and Exports**: Analysis of imported functions to identify potentially malicious capabilities.
- **Indicators**: Warnings indicating suspicious characteristics of the file.
- **Strings Analysis**: Extraction of readable strings within the binary for clues related to functionality and IOCs.

![PEStudio Analysis](../mnt/data/Screenshot 2025-03-14 004836.png)

## Dynamic Analysis
### Process Monitoring (ProcMon)
Process Monitor was used to observe file operations, registry modifications, and process activity. The tool highlighted suspicious activity such as:
- Creation of files with random filenames.
- Modifications to registry keys.
- Execution of encryption routines.

![ProcMon Analysis](../mnt/data/Screenshot 2025-03-14 024840.png)

### Network Analysis (Wireshark)
Wireshark was utilized to capture network traffic during the ransomware’s execution. Analysis of network packets revealed the following:
- Communication attempts to known command-and-control (C2) servers.
- Attempts to propagate via SMB protocol (Exploiting EternalBlue vulnerability).

![Wireshark Analysis](../mnt/data/Screenshot 2025-03-14 024925.png)

## Indicators of Compromise (IOCs)
- **File Extensions**: Encrypted files had a `.WNCRY` extension.
- **C2 Servers**: Attempts to connect to malicious IP addresses.
- **Registry Keys Modified**: Keys related to persistence mechanisms.

## Mitigation & Recommendations
- Apply security patches (e.g., MS17-010) to prevent exploitation via SMB protocol.
- Use network-based and host-based intrusion detection systems to detect malicious activities.
- Regularly back up critical data and maintain offline backups.

## Conclusion
The WannaCry ransomware analysis demonstrates the importance of using both static and dynamic analysis techniques. By understanding the malware’s behavior, defenders can create effective detection and mitigation strategies.

## References
- [Matt Kiely's Ransomware Analysis Methodology](https://example.com)  
- [WannaCry Analysis Reports](https://example.com)
