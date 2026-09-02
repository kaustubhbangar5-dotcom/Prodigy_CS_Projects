# PRODIGY_CS_04: Simple Keylogger Program

[![Track: Cyber Security](https://img.shields.io/badge/Track-Cyber_Security-blue.svg)](https://prodigyinfotech.dev)
[![Task: 04](https://img.shields.io/badge/Task-04-brightgreen.svg)](https://prodigyinfotech.dev)
[![Language: Python 3](https://img.shields.io/badge/Language-Python_3-yellow.svg)](https://www.python.org/)
[![Library: pynput](https://img.shields.io/badge/Library-pynput_1.7+-orange.svg)](https://pypi.org/project/pynput/)

---

> [!CAUTION]
> **LEGAL & ETHICAL DISCLAIMER**  
> This project is designed and implemented solely for **educational, academic, and authorized defensive security research** purposes as part of the Prodigy InfoTech Cyber Security Internship. Unauthorized interception, monitoring, or logging of keystrokes on systems without explicit prior permission is strictly illegal and violates cyber laws globally. The author assumes no liability for misuse of this software.

---

## Overview

This project is developed as part of **Task 04** for the **Prodigy InfoTech Cyber Security Internship Track**. It demonstrates how low-level peripheral input events (keyboard and mouse) are captured, parsed, and logged at the operating system level using Python's `pynput` library.

By understanding the mechanics of how input event listeners intercept hardware interrupts, security analysts can design effective **detection rules, endpoint protection controls, and anti-keylogging defenses**.

---

## Project Features

-  **Real-Time Keystroke Interception**: Captures alphanumeric characters and system key events as they occur across active windows.
-  **Readable Key Normalization**: Intelligently cleans string formatting (e.g., converts `'a'` to `a`, `Key.space` to a whitespace character, and `Key.enter` to a newline).
-  **Special Key Tagging**: Clearly formats non-printable and modifier keys such as `[BACKSPACE]`, `[CTRL]`, `[TAB]`, `[ALT]`, and `[CAPS_LOCK]`.
-  **Safe Exit Mechanism**: Intercepts the `ESC` key to cleanly terminate the asynchronous listener thread without hanging the process.
-  **Peripheral Input Simulation & Tracking**: Includes auxiliary modules demonstrating automated mouse relocation, automated keyboard typing, and real-time mouse coordinate tracking.
-  **File Persistence**: Appends formatted keystrokes in UTF-8 encoding directly to `log.txt`.

---

## Problem Statement

Create a basic keylogger program that records and logs keystrokes. Focus on logging the keys pressed and saving them to a file. Emphasize ethical considerations, permissions, and security awareness regarding how such tools operate and how systems are defended against unauthorized monitoring.

---

## Tools and Technologies

| Component | Technology / Library | Description |
| :---  :---  :--- 
| **Language** | Python 3.x | Core programming language |
| **Input Event Hooking** | `pynput.keyboard` | Global keyboard listener and controller |
| **Mouse Event Hooking** | `pynput.mouse` | Global mouse listener and controller |
| **Data Persistence** | File I/O (`open()`) | Appending formatted logs in UTF-8 encoding |
| **Security Domain** | Endpoint Security | Input monitoring, API hooking, and defensive telemetry |

---

## Architecture Diagram

```
                              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                              â”‚         USER KEYBOARD INPUT      â”‚
                              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                               â”‚
                                               â–¼
                              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                              â”‚   Operating System Input Queue   â”‚
                              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                               â”‚
                                               â–¼
                              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                              â”‚     pynput.keyboard.Listener     â”‚
                              â”‚     Global Hook Interception     â”‚
                              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                               â”‚
                                               â–¼
                              â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                              â”‚      Event Callback Function     â”‚
                              â”‚         write_to_file()          â”‚
                              â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                               â”‚
                         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                         â–¼                                           â–¼
             â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”                    â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
             â”‚ Key == Key.esc ?     â”‚                    â”‚  Character Parsing   â”‚
             â”‚ Return False (Exit)  â”‚                    â”‚  & Special Key Tag   â”‚
             â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                    â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
                                                                     â”‚
                                                                     â–¼
                                                         â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
                                                         â”‚ Append to 'log.txt'  â”‚
                                                         â”‚ (UTF-8 Plaintext)    â”‚
                                                         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

---

## Dashboard Screenshot / Execution Workflow

### 1. Terminal Console Execution (`main.py`)

```text
==================================================
  Prodigy InfoTech - Cyber Security Task 04: Keylogger
  [INFO] Keystrokes are being logged to 'log.txt'
  [INFO] Press 'ESC' to stop the keylogger.
==================================================

[INFO] Exiting keylogger...
```

### 2. Sample Output File (`log.txt`)

Below is an illustration of how captured keystrokes are recorded in a readable sentence structure:

```text
Hello World! 
This is a demonstration of Task 04. [BACKSPACE] 
Prodigy InfoTech Cyber Security Internship.
```

---

## Methods

### 1. Global Hooking Architecture
The application leverages the `pynput.keyboard.Listener` context manager, which binds a low-level hook (such as `WH_KEYBOARD_LL` on Windows or X11/Quartz on Unix/macOS) to intercept hardware keyboard messages before they are processed by target applications.

### 2. Character Sanitization Logic
- **Alphanumeric Keys**: Strips enclosing quote delimiters (`'h'` $
ightarrow$ `h`).
- **Whitespace & Structure**: Normalizes `Key.space` to `" "` and `Key.enter` to `"
"`.
- **Modifiers & Control Keys**: Transformed into structured bracketed tags like ` [BACKSPACE] `, ` [CTRL] `, or ` [ALT] `.
- **Termination Signal**: Evaluates if the incoming key matches `Key.esc`. Returning `False` stops the listener thread gracefully.

### 3. Peripheral Controllers (`control.py` & `listen.py`)
- `control.py`: Demonstrates software automation by repositioning the mouse cursor and invoking virtual keystrokes via `keyboard.type()`.
- `listen.py`: Monitors raw mouse `(x, y)` coordinate updates across the display surface.

---

## Key Insights & Defensive Security

Keyloggers represent a significant vector in credential harvesting and espionage. Understanding how they function enables cyber defenders to deploy robust countermeasures:

### 1. Detection Mechanisms
- **API Hook Auditing**: Modern Endpoint Detection and Response (EDR) solutions monitor calls to Windows API functions like `SetWindowsHookExA/W` and `GetAsyncKeyState`.
- **Behavioral Telemetry**: Antivirus engines analyze unauthorized processes attempting to spawn background hooks or write persistent input logs to disk.
- **Process Memory Scanning**: Detecting foreign DLL injection into legitimate system processes (`explorer.exe`, `svchost.exe`).

### 2. Defensive Countermeasures
- **Multi-Factor Authentication (MFA)**: Time-based One-Time Passwords (TOTP) and hardware security keys (FIDO2) ensure that stolen passwords alone cannot grant access.
- **Virtual On-Screen Keyboards**: Bypasses physical keyboard hooks for entering critical credentials.
- **Keystroke Encryption Drivers**: Specialized software encrypts keystroke data at the kernel keyboard driver level before user-mode hooks can capture it.
- **Least Privilege Access**: Restricting administrative privileges prevents untrusted applications from hooking global system inputs.

---

## How to Run this Project

### Prerequisites
- Python 3.8 or higher installed on your system.

### Step-by-Step Instructions

1. **Navigate to the Project Folder**:
   ```bash
   cd Prodigy_CS_04
   ```

2. **Install Required Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the Main Keylogger**:
   ```bash
   python main.py
   ```
   *Type keys in any window. Press **`ESC`** at any time to stop the logger and write output to `log.txt`.*

4. **Run Peripheral Demos**:
   - **Automated Mouse & Keyboard Simulation**:
     ```bash
     python control.py
     ```
   - **Real-Time Mouse Position Tracking**:
     ```bash
     python listen.py
     ```

---

## Results & Conclusion

### Summary of Modules

| Script | Purpose | Status |
| :---  :---  :--- 
| `main.py` | Core keystroke recording with readable formatting and ESC exit | âœ… Verified |
| `control.py` | Virtual mouse movement and automated keyboard typing simulation | âœ… Verified |
| `listen.py` | Real-time mouse movement listener and coordinate reporter | âœ… Verified |
| `log.txt` | Output text file storing intercepted keystrokes | âœ… Verified |

### Conclusion
Task 04 successfully demonstrates the principles of low-level input event listening and hardware simulation in Python. The implementation highlights both the operational mechanisms of keyloggers and the vital role of defensive controls such as MFA, EDR monitoring, and behavioral heuristics in protecting user endpoints.

---

## Future Work & Defensive Enhancements

-  **YARA Rule Development**: Write custom YARA and Sigma rules to detect keylogger signatures and hook execution patterns.
-  **Anti-Keylogger Daemon**: Build a defense script that monitors active process hooks and notifies users when an unauthorized application attempts to listen to system inputs.
-  **Input Obfuscation Research**: Research keystroke timing obfuscation and random dummy character injection techniques.

---

## Author & Contact

- **Author**: Kaustubh Bangar
- **Track**: Cyber Security (CS)
- **Organization**: Prodigy InfoTech
- **Task**: Task 04 - Simple Keylogger Program (`PRODIGY_CS_04`)
- **LinkedIn**: [Your LinkedIn Profile URL]
- **GitHub**: [Your GitHub Profile URL]
