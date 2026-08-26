# PRODIGY_CS_02: Pixel Manipulation for Image Encryption

[![Track: Cyber Security](https://img.shields.io/badge/Track-Cyber_Security-blue.svg)](https://prodigyinfotech.dev)
[![Task: 02](https://img.shields.io/badge/Task-02-brightgreen.svg)](https://prodigyinfotech.dev)
[![Language: Python 3](https://img.shields.io/badge/Language-Python_3-yellow.svg)](https://www.python.org/)
[![Library: Pillow](https://img.shields.io/badge/Library-Pillow_11-orange.svg)](https://python-pillow.org/)
[![Library: NumPy](https://img.shields.io/badge/Library-NumPy_2.2-blueviolet.svg)](https://numpy.org/)

---

## Overview

This project is developed as part of **Task 02** for the **Prodigy InfoTech Cyber Security Internship Track**. It provides a robust, high-performance image encryption and decryption application utilizing advanced **pixel manipulation techniques**, bitwise XOR transformations, modular intensity shifts, and key-seeded spatial coordinate permutations.

The application features both an interactive colorized Command Line Interface (CLI), scriptable flag execution, and an intuitive desktop Graphical User Interface (GUI) powered by Tkinter.

---

## Project Features

- 🔐 **Multiple Pixel Manipulation Modes**:
  - **Bitwise XOR Transformation (`xor`)**: Applies a key-derived keystream across pixel channels ($P \oplus K = C$).
  - **Swap & Modular Intensity Shift (`swap`)**: Applies modular arithmetic shift $(P + K) \pmod{256}$ and permutes Red and Blue channels.
  - **Spatial Pixel Position Shuffling (`shuffle`)**: Randomizes 2D pixel positions using key-seeded PRNG permutation.
  - **Combined Mode (`combined` - Default)**: Merges spatial coordinate shuffling with bitwise XOR transformation for maximum confusion and diffusion.
- 🖼️ **Multi-Format & Color Space Support**: Fully compatible with RGB, RGBA (transparent), and Grayscale (`L`) images.
- 🛡️ **Lossless Output Protection**: Automatically enforces and converts output file extensions to PNG/BMP to protect pixel bit-level integrity against lossy compression.
- 🖥️ **Dual User Interface**:
  - **Interactive CLI**: Guided step-by-step terminal prompts.
  - **Scriptable CLI Flags**: Direct command-line flag execution (`-e`, `-d`, `-i`, `-o`, `-k`, `-m`) for automated workflows.
  - **Tkinter Desktop GUI**: Graphical file browser and interface (`--gui`).
- 🧪 **Comprehensive Automated Testing**: Includes a 100% passing unit test suite (`test_image_encryptor.py`).

---

## Problem Statement

Develop a Python application that performs image encryption and decryption using pixel manipulation techniques. The application must:
1. Accept an input image file and a secret user passcode.
2. Manipulate raw pixel values (e.g., bitwise XOR, channel swapping, spatial shuffling).
3. Generate a visual obfuscated ciphertext image that obscures all visual features of the original image.
4. Guarantee 100% reversible bit-exact decryption to recover the original image when supplied with the correct secret key.

---

## Tools and Technologies

| Component | Technology / Library | Description |
| :--- | :--- | :--- |
| **Language** | Python 3.x | Core programming language |
| **Image Processing** | Pillow (PIL) | Image loading, mode conversion, and saving |
| **Array Manipulation** | NumPy | High-performance 2D/3D array matrix operations |
| **Hashing & Security** | hashlib (SHA-256) | Deterministic key seed derivation |
| **GUI Framework** | Tkinter | Native cross-platform desktop interface |
| **Testing** | unittest | Automated verification test suite |

---

## Architecture Diagram

```
                              ┌──────────────────────────────────┐
                              │           USER START             │
                              └────────────────┬─────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │     Select Mode (CLI / GUI)      │
                              └────────────────┬─────────────────┘
                                               │
                                  ┌────────────┴────────────┐
                                  ▼                         ▼
                      ┌──────────────────────┐   ┌──────────────────────┐
                      │  Encrypt Image (-e)  │   │  Decrypt Image (-d)  │
                      └──────────┬───────────┘   └──────────┬───────────┘
                                 │                          │
                                 ▼                          ▼
                      ┌──────────────────────┐   ┌──────────────────────┐
                      │ Input Image & Key K  │   │ Input Image & Key K  │
                      └──────────┬───────────┘   └──────────┬───────────┘
                                 │                          │
                                 └────────────┬─────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │      SHA-256 Key Derivation      │
                              │    Derive 64-bit PRNG Seed S     │
                              └───────────────┬──────────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │   Pixel Manipulation Engine      │
                              │  (Combined / XOR / Swap / Perm)  │
                              └───────────────┬──────────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │     Lossless Format Guard        │
                              │     (Enforce PNG / BMP Format)   │
                              └───────────────┬──────────────────┘
                                              │
                                              ▼
                              ┌──────────────────────────────────┐
                              │      Output Processed Image      │
                              └──────────────────────────────────┘
```

---

## Dashboard Screenshot

Below is an illustration of the Caesar & Pixel Encryption Interface and CLI workflow:

```
======================================================================
               PRODIGY INFOTECH - CYBER SECURITY TASK 02               
               PIXEL MANIPULATION IMAGE ENCRYPTION TOOL               
======================================================================

Select an Operation:
  [1] Encrypt Image
  [2] Decrypt Image
  [3] Launch Graphical Interface (GUI)
  [4] Exit

Enter your choice (1/2/3/4): 1

--- ENCRYPTION MODE ---
Enter input image path    : secret_photo.png
Enter output image path   : encrypted_photo.png
Enter secret key / passcode: MySecretPasscode123
Select Mode (combined/xor/swap/shuffle) [default: combined]: combined

----------------------------------------------------------------------
[+] Task completed successfully! Output saved to: encrypted_photo.png
----------------------------------------------------------------------
```

---

## Methods

### 1. Key Derivation Function (KDF)
User passcodes of arbitrary length are hashed using **SHA-256** to derive a deterministic 64-bit seed $S$:

$$S = \text{SHA-256}(K)_{[0..7]} \pmod{2^{64}}$$

This seed initializes NumPy's PCG64 Pseudo-Random Number Generator (PRNG) to ensure bit-exact reproducibility during decryption.

### 2. Bitwise XOR Transformation (`xor`)
Let $P_{x,y,c}$ represent the 8-bit intensity value of pixel channel $(x,y,c)$ and $K_{x,y,c} \in [0, 255]$ represent the key-derived keystream:

$$\text{Encryption: } C_{x,y,c} = P_{x,y,c} \oplus K_{x,y,c}$$
$$\text{Decryption: } P_{x,y,c} = C_{x,y,c} \oplus K_{x,y,c}$$

Since XOR is self-inverting ($(A \oplus B) \oplus B = A$), applying the identical keystream restores the exact original pixel values.

### 3. Modular Intensity Shift & Channel Swap (`swap`)
Pixel intensities are shifted using modular addition:

$$\text{Encryption: } C_{x,y,c} = (P_{x,y,c} + K_{x,y,c}) \pmod{256}$$
$$\text{Decryption: } P_{x,y,c} = (C_{x,y,c} - K_{x,y,c} + 256) \pmod{256}$$

Additionally, Red ($c=0$) and Blue ($c=2$) channels are swapped during encryption and restored during decryption.

### 4. Spatial Pixel Position Shuffling (`shuffle`)
The 2D/3D image array of dimensions $H \times W$ with $N = H \cdot W$ pixels is flattened. A permutation index array $\pi$ of length $N$ is generated using seed $S$:

$$\text{Encryption: } \text{Flat}_{\text{enc}}[i] = \text{Flat}_{\text{orig}}[\pi[i]]$$
$$\text{Decryption: } \text{Flat}_{\text{orig}}[i] = \text{Flat}_{\text{enc}}[\pi^{-1}[i]] \quad \text{where } \pi^{-1} = \text{argsort}(\pi)$$

---

## Key Insights

1. **Confusion and Diffusion (Shannon's Principles)**:
   - **Confusion**: Achieved via bitwise XOR and modular shifts, concealing the relationship between the key and ciphertext pixels.
   - **Diffusion**: Achieved via spatial pixel shuffling, spreading the visual structure across the entire pixel grid.
2. **Lossless vs. Lossy Image Compression**:
   - Pixel-based encryption **requires lossless storage (PNG, BMP)**.
   - Using lossy formats (JPEG) alters pixel values due to Discrete Cosine Transform (DCT) quantization, which permanently destroys bitwise cryptographic reversibility.
3. **Cryptanalytic Security**:
   - Simple pixel permutation alone preserves the image histogram (color distribution).
   - Combining spatial permutation with bitwise XOR transformation breaks histogram patterns completely, yielding maximum entropy.

---

## How to Run this Project

### Prerequisites
- Python 3.8 or higher.

### Step-by-Step Execution

1. **Navigate to the Project Directory**:
   ```bash
   cd Prodigy_CS_02
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run Interactive Menu**:
   ```bash
   python image_encryptor.py
   ```

4. **Run via Scriptable Command-Line Flags**:
   - **Encrypt**:
     ```bash
     python image_encryptor.py -e -i sample.png -o encrypted.png -k "SecretPasscode123" -m combined
     ```
   - **Decrypt**:
     ```bash
     python image_encryptor.py -d -i encrypted.png -o decrypted.png -k "SecretPasscode123" -m combined
     ```

5. **Launch Desktop GUI**:
   ```bash
   python image_encryptor.py --gui
   ```

---

## Results & Conclusion

### Automated Test Verification Matrix (`test_image_encryptor.py`)

Executing `python test_image_encryptor.py` verifies all 7 unit tests:

```
.......
----------------------------------------------------------------------
Ran 7 tests in 0.667s

OK
```

| Test Case | Test Description | Status |
| :--- | :--- | :--- |
| `test_key_derivation` | Deterministic SHA-256 seed generation | ✅ Passed |
| `test_xor_encryption` | Bitwise XOR reversible encryption/decryption | ✅ Passed |
| `test_swap_encryption` | Channel swapping & modular intensity shift | ✅ Passed |
| `test_shuffle_encryption` | Spatial position permutation & inversion | ✅ Passed |
| `test_combined_encryption` | Combined shuffling + XOR mode | ✅ Passed |
| `test_different_keys` | Verifies wrong keys fail to decrypt | ✅ Passed |
| `test_grayscale_and_rgba` | Compatibility across RGB, RGBA, and Grayscale | ✅ Passed |

### Conclusion
The **Prodigy_CS_02** project fulfills all requirements for Task 02 of the Cyber Security track. It delivers high-entropy image obfuscation while guaranteeing 100% lossless bit-exact restoration upon decryption.

---

## Future Work

- 🔒 **AES-GCM Authenticated Pixel Encryption**: Integrate AES-256-GCM authenticated encryption for cryptographically secure payload protection.
- 👁️ **Steganographic Image Obfuscation**: Hide encrypted pixel data within innocent cover images using Least Significant Bit (LSB) steganography.
- 🌐 **Web-Based Image Security Portal**: Create a WebAssembly/React web application interface for browser-based image encryption.

---

## Author & Contact

- **Author**: Kaustubh Bangar
- **Track**: Cyber Security (CS)
- **Organization**: Prodigy InfoTech
- **Task**: Task 02 - Pixel Manipulation for Image Encryption (`PRODIGY_CS_02`)
- **LinkedIn**: [Your LinkedIn Profile URL]
- **GitHub**: [Your GitHub Profile URL]
