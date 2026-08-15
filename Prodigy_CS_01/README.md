# PRODIGY_CS_01: Caesar Cipher Implementation

[![Track: Cyber Security](https://img.shields.io/badge/Track-Cyber_Security-blue.svg)](https://prodigyinfotech.dev)
[![Task: 01](https://img.shields.io/badge/Task-01-brightgreen.svg)](https://prodigyinfotech.dev)
[![Language: Python 3](https://img.shields.io/badge/Language-Python_3-yellow.svg)](https://www.python.org/)

---

## Overview

This project is developed as part of **Task 01** for the **Prodigy InfoTech Cyber Security Internship Track**. It provides a fully functional, interactive Python command-line application that encrypts and decrypts text using the classic **Caesar Cipher** cryptographic algorithm.

The Caesar Cipher is one of the foundational building blocks of classical cryptography. It works by replacing each letter in a plaintext message with another letter shifted by a fixed number of positions down the alphabet.

---

## Project Features

- 🔐 **Dual Mode Execution**: Interactive selection for both **Encryption** and **Decryption** modes.
- 🔤 **Case Preservation**: Intelligently preserves uppercase (`A-Z`) and lowercase (`a-z`) formatting.
- 🛡️ **Non-Alphabetic Character Immunity**: Leaves spaces, punctuation marks, digits, and special characters unmodified.
- 🔄 **Boundary Wrap-Around**: Uses modular arithmetic to ensure characters wrap around alphabet boundaries (`Z` $\rightarrow$ `A` or `z` $\rightarrow$ `a`).
- 🔢 **Extended Key Flexibility**: Handles negative shifts as well as shift values larger than the alphabet length ($k > 26$) using modulo 26 arithmetic.
- ⚠️ **Input Sanitization & Exception Handling**: Built-in validation prevents program crashes when users enter invalid input types (e.g., non-integer shift values).

---

## Problem Statement

Create a Python program capable of encrypting and decrypting text messages using the Caesar Cipher algorithm. The application must:
1. Accept custom text input and shift values (keys) from the user.
2. Perform character-level transformations based on the Caesar Cipher shift logic.
3. Allow users to seamlessly decrypt previously encrypted messages by reversing the shift key.
4. Ensure robustness across edge cases (mixed casing, non-alphabet symbols, large keys).

---

## Tools and Technologies

| Component | Technology / Concept |
| :--- | :--- |
| **Language** | Python 3.x |
| **Libraries** | Python Standard Library (`ord()`, `chr()`, `sys`) |
| **Domain** | Classical Cryptography, Information Security |
| **Key Concepts** | Substitution Ciphers, ASCII Code Point Mapping, Modular Arithmetic |

---

## Architecture Diagram

```
                              ┌──────────────────────────────────┐
                              │           USER START             │
                              └────────────────┬─────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │      CLI Menu Choice (1/2/3)     │
                              └────────────────┬─────────────────┘
                                               │
                                  ┌────────────┴────────────┐
                                  ▼                         ▼
                      ┌──────────────────────┐   ┌──────────────────────┐
                      │  1. Encrypt Message  │   │  2. Decrypt Message  │
                      └──────────┬───────────┘   └──────────┬───────────┘
                                 │                          │
                                 ▼                          ▼
                      ┌──────────────────────┐   ┌──────────────────────┐
                      │ Input Text & Shift k │   │ Input Text & Shift k │
                      └──────────┬───────────┘   └──────────┬───────────┘
                                 │                          │
                                 └────────────┬─────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │     Caesar Cipher Engine         │
                              │  Loop through each character     │
                              └───────────────┬──────────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │    Is Character Alphabetic?      │
                              └───────┬──────────────────┬───────┘
                           YES │                  │ NO
                               ▼                  ▼
             ┌──────────────────────────┐   ┌──────────────────────────┐
             │ Convert to 0-25 Index    │   │ Keep Character Unchanged │
             │  E(x) = (x + k) mod 26   │   └────────────┬─────────────┘
             │  D(x) = (x - k) mod 26   │                │
             └────────────┬─────────────┘                │
                          │                              │
                          └──────────────┬───────────────┘
                                         │
                                         ▼
                              ┌──────────────────────────────────┐
                              │  Reconstruct Transformed String  │
                              └────────────────┬─────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │     Display Output Result        │
                              └──────────────────────────────────┘
```

---

## Dashboard Screenshot

Below is an illustration of the Caesar Cipher Interactive CLI Console Interface:

```
=======================================================
        PRODIGY INFOTECH - CYBER SECURITY TASK 01      
                 CAESAR CIPHER TOOL
=======================================================

Select an Operation:
  [1] Encrypt Message
  [2] Decrypt Message
  [3] Exit

Enter your choice (1/2/3): 1

--- ENCRYPTION MODE ---      
Enter the plaintext message: KAUSTUBH
Enter shift value (key): 5

----------------------------------------
Original Text  : KAUSTUBH
Shift Key      : 5
Encrypted Text : PFZXYZGM
----------------------------------------

Select an Operation:
  [1] Encrypt Message
  [2] Decrypt Message
  [3] Exit

Enter your choice (1/2/3): 2

--- DECRYPTION MODE ---      
Enter the encrypted message: PFZXYZGM
Enter shift value (key): 5

----------------------------------------
Ciphertext     : PFZXYZGM
Shift Key      : 5
Decrypted Text : KAUSTUBH
----------------------------------------

Select an Operation:
  [1] Encrypt Message
  [2] Decrypt Message
  [3] Exit

Enter your choice (1/2/3): 3

Thank you for using the Caesar Cipher Tool! Exiting program...
```

---

## Methods

### 1. Mathematical Formulas

- **Encryption Formula**:
  $$E(x) = (x + k) \pmod{26}$$

- **Decryption Formula**:
  $$D(x) = (x - k) \pmod{26}$$

Where:
- $x$ is the 0-indexed position of the letter in the alphabet ($0 \le x \le 25$).
- $k$ is the shift key value.
- $26$ is the total number of letters in the English alphabet.

### 2. ASCII Transformation Logic

Characters in Python are converted to ASCII code points using `ord()` and back to characters using `chr()`:
- **Uppercase Mapping**: $\text{Index} = \text{ord}(\text{char}) - \text{ord}(\text{'A'})$
- **Lowercase Mapping**: $\text{Index} = \text{ord}(\text{char}) - \text{ord}(\text{'a'})$
- **Shift Application**: $\text{New Index} = (\text{Index} + k) \pmod{26}$
- **Re-encoding**: $\text{New Char} = \text{chr}(\text{Base ASCII} + \text{New Index})$

### 3. Input Validation Method

A wrapper function `get_integer_input()` handles exception catching using `try...except ValueError` loops to gracefully prompt users if non-integer characters are supplied for key values.

---

## Key Insights

1. **Foundational Cryptography**: Caesar Cipher illustrates key substitution concepts used in modern stream and block ciphers.
2. **Cryptanalytic Vulnerabilities**:
   - **Brute Force Key Space**: The key space consists of only 25 valid keys for the English alphabet. A modern computer can iterate through all possible shifts in microseconds.
   - **Frequency Analysis**: Single substitution ciphers maintain language letter frequency distribution. In English, letters like `E`, `T`, `A`, and `O` occur with highest frequency, allowing ciphertext to be broken without knowing the key.
3. **Difference between Classical and Modern Encryption**: Modern ciphers (such as AES-256) utilize complex substitution-permutation networks (SPN) and 256-bit keys ($2^{256}$ search space) to prevent both frequency analysis and brute-force cracking.

---

## How to Run this Project

### Prerequisites
- Python 3.6 or higher installed on your operating system.

### Step-by-Step Instructions

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/kaustubhbangar5-dotcom/Prodigy_CS_Projects.git
   ```

2. **Navigate into the Project Folder**:
   ```bash
   cd PRODIGY_CS_01
   ```

3. **Run the Application**:
   ```bash
   python caesar_cipher.py
   ```

---

## Results & Conclusion

### Test Verification Results

| Test Scenario | Plaintext / Input | Key Shift | Expected Output | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Basic Encryption** | `Hello World` | `3` | `Khoor Zruog` | ✅ Passed |
| **Basic Decryption** | `Khoor Zruog` | `3` (Reversed) | `Hello World` | ✅ Passed |
| **Alphabet Wrap-Around** | `XYZ` | `3` | `ABC` | ✅ Passed |
| **Large Key ($k > 26$)** | `ABC` | `29` ($29 \pmod{26} = 3$) | `DEF` | ✅ Passed |
| **Punctuation & Numbers** | `Security 2026!` | `5` | `Xjhzwnyd 2026!` | ✅ Passed |

### Conclusion
The Caesar Cipher project successfully satisfies all requirements for **Task 01** of the Prodigy InfoTech Cyber Security track. It accurately executes encryption and decryption while preserving document structure, case sensitivity, and handling edge cases gracefully.

---

## Future Work

- 🖥️ **Graphical User Interface (GUI)**: Develop a desktop interface using Tkinter or PyQt for easier user interaction.
- 🔓 **Automated Frequency Analysis Solver**: Implement an automated cryptanalysis solver that breaks ciphertext without requiring a known key by computing letter frequency distributions.
- 🌐 **Web-Based Cipher Suite**: Expand into a browser-based cryptography sandbox supporting multiple classical ciphers (Vigenère, Playfair, ROT13, Vernam).

---

## Author & Contact

- **Author**: Kaustubh Bangar
- **Track**: Cyber Security (CS)
- **Organization**: Prodigy InfoTech
- **Task**: Task 01 - Implement Caesar Cipher (PRODIGY_CS_01)
- **LinkedIn**: [https://www.linkedin.com/in/kaustubh-bangar-546259351]
- **GitHub**: [https://github.com/kaustubhbangar5-dotcom]
