# 🛡️ MINI-IDS

### Lightweight Real-Time Intrusion Detection System

## 📌 Table of Contents

## 📖 Overview

**MINI-IDS** is a lightweight, real-time network intrusion detection system built with **C++**. It captures live network traffic, detects brute-force attacks on critical ports (SSH-22, RDP-3389, FTP-21), automatically blocks suspicious IPs, and saves all logs persistently.

### 🎯 Purpose

- Demonstrate real-world application of **Data Structures & Algorithms**
- Provide an **educational** IDS for cybersecurity beginners
- Detect and block **brute-force attacks** in real-time
- Save **ALL captured packets** to a log file for analysis

---

## ✨ Features

### 📡 Capture & Monitoring

| # | Feature | Description |
|---|---------|-------------|
| 1 | Real-time packet capture | Captures live network traffic |
| 2 | Packet display | Shows packets with colored output |
| 3 | Interface listing | Lists all available network interfaces |
| 4 | Interface selection | Select by number (no need to type GUID) |

### 🎯 Attack Detection

| # | Feature | Description |
|---|---------|-------------|
| 5 | SSH Brute-force | Detects attacks on port 22 |
| 6 | RDP Brute-force | Detects attacks on port 3389 |
| 7 | FTP Brute-force | Detects attacks on port 21 |
| 8 | Port Scan detection | Detects port scanning activity |
| 9 | DDoS detection | Detects packet flood attacks |

### 🛡️ Protection

| # | Feature | Description |
|---|---------|-------------|
| 10 | Auto IP blocking | Blocks suspicious IPs immediately |
| 11 | Blocklist | View all blocked IPs |
| 12 | Whitelist | Never block trusted IPs |
| 13 | O(1) lookup | Hash set for fast IP checking |

### 📁 Logging & Storage

| # | Feature | Description |
|---|---------|-------------|
| 14 | All packets log | Saves EVERY packet to `all_packets_log.txt` |
| 15 | Attack logs | Saves only attack records |
| 16 | Persistent storage | Logs survive program restarts |
| 17 | Auto-load on startup | Loads previous logs automatically |

### 🔍 Search & Sort

| # | Feature | Algorithm | Complexity |
|---|---------|-----------|------------|
| 18 | Linear search | Sequential | O(n) |
| 19 | Binary search | Divide & conquer | O(log n) |
| 20 | Bubble sort | Adjacent swaps | O(n²) |
| 21 | Selection sort | Find minimum & swap | O(n²) |

### 📤 Export

| # | Feature | Format |
|---|---------|--------|
| 22 | Export logs | JSON format |
| 23 | Export logs | CSV format |
| 24 | Backup | Save all data |

### 🎨 User Interface

| # | Feature | Description |
|---|---------|-------------|
| 25 | Colorful CLI | Professional colored output |
| 26 | Password protection | Password: `porosh` |
| 27 | Intuitive menu | Number-based navigation |
| 28 | Stop capture | Press `q` to stop (program continues) |

---

## 📦 Requirements

### Hardware Requirements

| Component | Minimum |
|-----------|---------|
| RAM | 4GB |
| Storage | 100MB free |
| Network | Wi-Fi or Ethernet |

### Software Requirements

| Software | Download Link |
|----------|---------------|
| **Windows 10/11** or **Linux** | - |
| **MSYS2 UCRT64** (Windows) | [https://www.msys2.org/](https://www.msys2.org/) |
| **Npcap** (Windows) | [https://npcap.com/](https://npcap.com/) |
| **Npcap SDK** (Windows) | [https://npcap.com/](https://npcap.com/) |
| **libpcap-dev** (Linux) | `sudo apt install libpcap-dev` |
| **g++ compiler** | Included in MSYS2 / Linux |

---

## 🔧 Installation Guide

### 🪟 Windows Installation (Step by Step)

#### Step 1: Install MSYS2 UCRT64

1. Go to [https://www.msys2.org/](https://www.msys2.org/)
2. Download `msys2-x86_64-latest.exe`
3. Install with default settings
4. From Start Menu, open **MSYS2 UCRT64**

#### Step 2: Install Npcap Driver

1. Go to [https://npcap.com/](https://npcap.com/)
2. Download `npcap-1.xx.exe`
3. **Run as Administrator**
4. Check ✅ **"Install in WinPcap API-compatible Mode"**
5. Click Install → Restart computer

#### Step 3: Download Npcap SDK

1. Go to [https://npcap.com/](https://npcap.com/)
2. Download `npcap-sdk-1.xx.zip`
3. Extract to `C:\npcap-sdk`

#### Step 4: Download MINI-IDS Code

```bash
cd "/c/Users/YourUsername/Downloads"
git clone https://github.com/yourusername/MINI-IDS.git
# OR manually download the code and save as ids.cpp
```

#### Step 5: Compile the Code

```bash
cd "/c/Users/YourUsername/Downloads"
g++ -o ids.exe ids.cpp -I"C:/npcap-sdk/Include" -L"C:/npcap-sdk/Lib/x64" -lwpcap -lPacket -lws2_32 -lpthread -static
```

---

### 🐧 Linux (Kali/Ubuntu) Installation

#### Step 1: Install libpcap and g++

```bash
sudo apt update
sudo apt install libpcap-dev g++ -y
```

#### Step 2: Download Code

```bash
git clone https://github.com/yourusername/MINI-IDS.git
cd MINI-IDS
```

#### Step 3: Compile

```bash
g++ -o ids ids.cpp -lpcap -lpthread
```

---

## 🚀 How to Run

### Windows (UCRT64 Terminal)

```bash
# Step 1: Open MSYS2 UCRT64 from Start Menu

# Step 2: Navigate to the folder
cd "/c/Users/LAPTOP GADGET/Downloads"

# Step 3: Run the program
./ids.exe

# Step 4: Enter password
porosh
```

### Windows (Command Prompt as Administrator)

```cmd
cd "C:\Users\LAPTOP GADGET\Downloads"
ids.exe
```

### Linux

```bash
cd /path/to/MINI-IDS
sudo ./ids
```

---

## 📖 How to Use

### Main Menu Overview

```
╔════════════════════════════════════════════════════════════════════╗
║                           MAIN MENU                                ║
╠════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║   [1]  START Real-Time Monitoring                                 ║
║   [2]  View Live Statistics                                       ║
║   [3]  View Blocked IP List                                       ║
║   [4]  Search Logs                                                ║
║   [5]  Sort Logs                                                  ║
║   [6]  Export Logs (JSON/CSV)                                     ║
║   [7]  Configuration Settings                                     ║
║   [8]  View Attack History                                        ║
║   [9]  Unblock IP                                                 ║
║   [10] IP Ranking Report                                          ║
║   [11] Simulate Attack                                            ║
║   [12] Save & Backup All Data                                     ║
║   [0]  Exit                                                       ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
```

### Step-by-Step Usage

#### 🔹 Option 1: List Network Interfaces
```
Enter your choice: 1
```
Shows all available network interfaces with numbers.

#### 🔹 Option 2: Start Real-Time Capture
```
Enter your choice: 2
Enter interface number: 4   (for Wi-Fi)
```
- Live packets will appear
- Press `q` to stop capture (program continues)
- Press `s` to view live statistics

#### 🔹 Option 3: View Blocked IPs
```
Enter your choice: 3
```
Shows list of automatically blocked IPs.

#### 🔹 Option 4: Search Logs (Linear Search)
```
Enter your choice: 4
Enter IP: 45.33.22.11
```
Finds attack records for the given IP.

#### 🔹 Option 5: Sort Logs
```
Enter your choice: 5
1. By Time (Newest)
2. By Time (Oldest)
3. By Severity
```
Sorts attack logs using Bubble/Selection sort.

#### 🔹 Option 6: Export Logs
```
Enter your choice: 6
1. JSON
2. CSV
```
Exports all attack logs to a file.

#### 🔹 Option 7: Configuration
```
Enter your choice: 7
1. Brute-force threshold: 5 attempts/min
2. Port scan threshold: 20 ports/10s
3. DDoS threshold: 100 pkt/s
4. Alerts: ON
```
Change detection thresholds.

#### 🔹 Option 8: View Attack History
```
Enter your choice: 8
```
Shows all detected attacks with timestamps.

#### 🔹 Option 9: Unblock IP
```
Enter your choice: 9
Select IP number to unblock: 1
```
Removes IP from blocklist.

#### 🔹 Option 10: IP Ranking
```
Enter your choice: 10
```
Shows top attackers by risk score.

#### 🔹 Option 11: Simulate Attack (Demo)
```
Enter your choice: 11
1. Brute-force
2. Port Scan
3. DDoS
```
Simulates an attack for testing/demo.

#### 🔹 Option 12: Save Backup
```
Enter your choice: 12
```
Saves all data (blocklist, logs, config).

#### 🔹 Option 0: Exit
```
Enter your choice: 0
```
Saves data and exits program.

---

## 📁 File Structure

After running the program, these files will be created:

```
Downloads/
├── ids.exe                 # Compiled program
├── ids.cpp                 # Source code
├── all_packets_log.txt     # ALL captured packets (every single packet!)
├── attack_logs.txt         # Only attack records
├── blocklist.txt           # Blocked IP addresses
├── config.txt              # User configuration settings
├── ids_export_*.json       # Exported logs (JSON format)
└── ids_export_*.csv        # Exported logs (CSV format)
```

### 📄 all_packets_log.txt Sample Output

```
========================================
MINI-IDS - ALL PACKETS LOG
========================================

[#1] Time: Sat Jun 14 10:30:15 2025
     Source: 192.168.1.100:54321
     Destination: 10.0.0.5:80
     Protocol: TCP
     -----------------------------------------
[#2] Time: Sat Jun 14 10:30:16 2025
     Source: 45.33.22.11:12345
     Destination: 192.168.1.100:22
     Protocol: TCP
     -----------------------------------------
```

### 📄 attack_logs.txt Sample Output

```
1|Sat Jun 14 10:30:20 2025|45.33.22.11|BRUTE-FORCE|BLOCKED
2|Sat Jun 14 10:30:25 2025|203.0.113.45|PORT SCAN|BLOCKED
```

---

## ⚠️ Troubleshooting

| Problem | Solution |
|---------|----------|
| `g++: command not found` | Use **MSYS2 UCRT64** terminal (not regular CMD) |
| `pcap.h: No such file or directory` | Download Npcap SDK and add `-I` path |
| `cannot find -lwpcap` | Add `-L"path/to/Lib/x64"` to compile command |
| `Access Denied` | Run terminal as **Administrator** |
| No packets captured | Check Wi-Fi/Ethernet is connected |
| Wrong interface selected | Press `1` to list interfaces, then choose correct number |
| Compilation error | Ensure code is saved as `ids.cpp` (not `.txt`) |

---
## 👥 Contributors

| Name | ID |
|------|-----|
| **Saydi Hasan Porosh** | 2304026 |
**Department:** Cyber Security Engineering  
**University:** University of Frontier Technology, Bangladesh  

## 📜 License

This project is for **educational purposes** as part of coursework.

---

## 📞 Contact

For any issues or questions, please contact the contributors.

Phone:017143995461
Email:2304026@uftb.ac.bd
FACEBOOK:

**⭐ Star this repository if you found it helpful!**


## 🎯 Quick Reference Card

| Action | Command / Key |
|--------|---------------|
| Compile (Windows) | `g++ -o ids.exe ids.cpp -I"C:/npcap-sdk/Include" -L"C:/npcap-sdk/Lib/x64" -lwpcap -lPacket -lws2_32 -lpthread -static` |
| Compile (Linux) | `g++ -o ids ids.cpp -lpcap -lpthread` |
| Run (Windows) | `./ids.exe` |
| Run (Linux) | `sudo ./ids` |
| Password | `porosh` |
| Stop capture | `q` |
| Show stats | `s` |
| Exit program | `0` |

---

** Happy Network Monitoring! Stay Secure!**
