# Prodigy InfoTech - Cyber Security Internship Projects

[![Track: Cyber Security](https://img.shields.io/badge/Track-Cyber_Security-blue.svg)](https://prodigyinfotech.dev)
[![Organization: Prodigy InfoTech](https://img.shields.io/badge/Organization-Prodigy_InfoTech-black.svg)](https://prodigyinfotech.dev)
[![Completed Tasks: 5/5](https://img.shields.io/badge/Tasks-5%2F5%20Completed-brightgreen.svg)](https://prodigyinfotech.dev)
[![Language: Python 3](https://img.shields.io/badge/Language-Python_3-yellow.svg)](https://www.python.org/)

Welcome to my portfolio repository for the **Prodigy InfoTech Cyber Security Internship Track**. This repository houses the complete source code, automated test suites, documentation, and user interfaces for all 5 internship tasks.

---

## Projects & Tasks Directory

| Task ID | Project Title | Key Focus & Domain | Tech Stack | Status |
| :--- | :--- | :--- | :--- | :--- |
| **[PRODIGY_CS_01](./Prodigy_CS_01)** | [Caesar Cipher Tool](./Prodigy_CS_01) | Classical Cryptography, Substitution Ciphers, ASCII & Modular Math | `Python 3` | `Completed` |
| **[PRODIGY_CS_02](./Prodigy_CS_02)** | [Pixel Manipulation Image Encryptor](./Prodigy_CS_02) | Image Processing, Bitwise XOR, Spatial Pixel Shuffling, Tkinter GUI | `Python 3`, `Pillow`, `NumPy`, `Tkinter` | `Completed` |
| **[PRODIGY_CS_03](./Prodigy_CS_03)** | [Password Complexity Checker](./Prodigy_CS_03) | Authentication Security, Shannon Bit Entropy, Password Generator, Tkinter GUI | `Python 3`, `re`, `math`, `secrets`, `Tkinter` | `Completed` |
| **[PRODIGY_CS_04](./Prodigy_CS_04)** | [Simple Keylogger & Input Monitoring](./Prodigy_CS_04) | OS Input Event Hooking, Peripheral Automation, Defensive EDR Awareness | `Python 3`, `pynput` | `Completed` |
| **[PRODIGY_CS_05](./Prodigy_CS_05)** | [Network Packet Analyzer](./Prodigy_CS_05) | Raw Socket Sniffing, Multi-Layer Protocol Decoding, Hex/ASCII Dump, PCAP Exporter | `Python 3`, `socket`, `struct`, `Tkinter` | `Completed` |

---

## Repository Architecture

```text
Prodigy_CS_Projects/
|-- Prodigy_CS_01/                 # Task 01: Caesar Cipher
|   |-- caesar_cipher.py           # Core Cipher Engine & CLI
|   |-- README.md                  # Detailed Documentation
|   +-- .gitignore
|
|-- Prodigy_CS_02/                 # Task 02: Pixel Manipulation Image Encryption
|   |-- image_encryptor.py         # Multi-mode Image Encryption & GUI
|   |-- test_image_encryptor.py    # Unit Test Suite (7/7 passed)
|   |-- requirements.txt           # Dependencies (Pillow, NumPy)
|   |-- README.md                  # Comprehensive Documentation
|   +-- .gitignore
|
|-- Prodigy_CS_03/                 # Task 03: Password Complexity Checker
|   |-- password_checker.py        # Strength Evaluator, Generator & GUI
|   |-- test_password_checker.py   # Unit Test Suite (5/5 passed)
|   |-- screenshots/               # GUI Dashboard Screenshots
|   |-- requirements.txt
|   |-- README.md                  # 12-Section Project Documentation
|   +-- .gitignore
|
|-- Prodigy_CS_04/                 # Task 04: Simple Keylogger Program
|   |-- main.py                    # Keystroke Recording & Formatting
|   |-- control.py                 # Mouse & Keyboard Simulation Demos
|   |-- listen.py                  # Mouse Event Listener
|   |-- requirements.txt           # Dependencies (pynput)
|   |-- README.md                  # Ethical Disclaimer & Architecture
|   +-- .gitignore
|
|-- Prodigy_CS_05/                 # Task 05: Network Packet Analyzer
|   |-- packet_analyzer.py         # Raw Socket Sniffer, Protocol Decoder & GUI
|   |-- test_packet_analyzer.py    # Unit Test Suite (5/5 passed)
|   |-- screenshots/               # Live GUI Packet Sniffer Screenshots
|   |-- requirements.txt
|   |-- README.md                  # RFC Decoding Specs & Wireshark Dumps
|   +-- .gitignore
|
+-- README.md                      # Main Repository Portfolio README
```

---

## Quick Start & Execution Guide

### 1. Clone the Repository

```bash
git clone https://github.com/kaustubhbangar5-dotcom/Prodigy_CS_Projects.git
cd Prodigy_CS_Projects
```

---

### 2. Running Individual Projects

#### Task 01: Caesar Cipher
```bash
cd Prodigy_CS_01
python caesar_cipher.py
```

#### Task 02: Pixel Manipulation Image Encryption
```bash
cd ../Prodigy_CS_02
pip install -r requirements.txt
python image_encryptor.py --gui
```

#### Task 03: Password Complexity Checker
```bash
cd ../Prodigy_CS_03
python password_checker.py --gui
```

#### Task 04: Simple Keylogger Program
```bash
cd ../Prodigy_CS_04
pip install -r requirements.txt
python main.py
```

#### Task 05: Network Packet Analyzer
```bash
cd ../Prodigy_CS_05
python packet_analyzer.py --gui
# Or run CLI simulation mode:
python packet_analyzer.py --simulate -c 10
```

---

## Cybersecurity Domains Practiced

1. **Cryptography**: Substitution ciphers, modular arithmetic, XOR keystreams, SHA-256 key derivation functions (KDF), and lossless compression security.
2. **Authentication Security**: Password strength scoring, Shannon Bit Entropy calculations ($E = L \times \log_2(R)$), dictionary attack resistance, and cryptographically secure PRNG generation (`secrets`).
3. **Endpoint & Input Security**: Low-level OS hardware hooking (`pynput`), API hook analysis (`SetWindowsHookEx`), and defensive mitigation strategies (MFA, on-screen keyboards, EDR telemetry).
4. **Network Defense & Packet Analysis**: Raw socket manipulation, binary struct header unpacking (IPv4, TCP, UDP, ICMP), port service resolution, Wireshark Hex/ASCII payload analysis, and PCAP file generation.

---

## Ethical & Legal Disclaimer

> [!CAUTION]
> All projects in this repository are developed strictly for **educational, academic, and authorized defensive security learning purposes** in accordance with the Prodigy InfoTech Internship curriculum. Unauthorized network sniffing, credential capture, or system monitoring without explicit permission is strictly illegal. Always adhere to ethical hacking and responsible disclosure standards.

---

## Author

- **Kaustubh Bangar**
- Internship Track: **Cyber Security (CS)**
- Organization: **Prodigy InfoTech**
- GitHub: [kaustubhbangar5-dotcom](https://github.com/kaustubhbangar5-dotcom)
- Repository: [Prodigy_CS_Projects](https://github.com/kaustubhbangar5-dotcom/Prodigy_CS_Projects.git)
- LinkedIn: [kaustubh-bangar-546259351](https://www.linkedin.com/in/kaustubh-bangar-546259351/)

