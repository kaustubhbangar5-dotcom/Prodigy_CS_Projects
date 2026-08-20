# PRODIGY_CS_02: Pixel Manipulation for Image Encryption

[![Track: Cyber Security](https://img.shields.io/badge/Track-Cyber_Security-blue.svg)](https://prodigyinfotech.dev)
[![Task: 02](https://img.shields.io/badge/Task-02-brightgreen.svg)](https://prodigyinfotech.dev)
[![Language: Python 3](https://img.shields.io/badge/Language-Python_3-yellow.svg)](https://www.python.org/)
[![Library: Pillow](https://img.shields.io/badge/Library-Pillow_11-orange.svg)](https://python-pillow.org/)
[![Library: NumPy](https://img.shields.io/badge/Library-NumPy_2.2-blueviolet.svg)](https://numpy.org/)

---

## Overview

This project is developed as part of **Task 02** for the **Prodigy InfoTech Cyber Security Internship Track**. It provides a robust, high-performance image encryption and decryption application utilizing advanced **pixel manipulation techniques**, bitwise XOR transformations, modular arithmetic intensity shifts, and key-seeded spatial coordinate permutations.

The application includes both an interactive colorized Command Line Interface (CLI) and an intuitive Graphical User Interface (GUI) powered by Tkinter.

---

## Project Features

- 🔐 **Multiple Encryption Operations**:
  - **Bitwise XOR Transformation (`xor`)**: Applies a key-derived keystream across pixel channels ($P \oplus K = C$).
  - **Swap & Modular Intensity Shift (`swap`)**: Applies modular arithmetic shift $(P + K) \pmod{256}$ and permutes Red and Blue channels.
  - **Spatial Pixel Position Shuffling (`shuffle`)**: Randomizes pixel positions across the grid using key-seeded PRNG permutation.
  - **Combined Mode (`combined` - Default)**: Merges spatial coordinate shuffling with bitwise XOR transformation for maximum confusion and diffusion.
- 🎨 **Multi-Format & Color Space Support**: Fully compatible with RGB, RGBA (transparent), and Grayscale (`L`) images.
- 🛡️ **Lossless Output Guard**: Automatically detects and redirects output file extensions to PNG/BMP to protect pixel integrity against lossy JPEG compression.
- 💻 **Dual User Interface**:
  - **Interactive CLI**: Colorized terminal UI with guided step-by-step prompts.
  - **Batch CLI Flags**: Direct command-line flag execution (`-e`, `-d`, `-i`, `-o`, `-k`, `-m`) for scripting and automation.
  - **Tkinter Desktop GUI**: Graphical file browser and interface (`--gui`).
- 🧪 **Comprehensive Automated Testing**: Includes a 100% passing unit test suite (`test_image_encryptor.py`).

---

## Mathematical & Cryptographic Foundations

### 1. Key Derivation Function (KDF)
User passcodes of arbitrary length are hashed using **SHA-256** to derive a deterministic 64-bit seed value $S$:
$$S = \text{SHA-256}(K)_{[0..7]} \pmod{2^{64}}$$
This seed initializes NumPy's PCG64 Pseudo-Random Number Generator (PRNG) to ensure bit-exact reproducibility for encryption and decryption.

### 2. Bitwise XOR Transformation (`xor`)
Let $P_{x,y,c}$ represent the 8-bit intensity value of pixel channel $(x,y,c)$ and $K_{x,y,c} \in [0, 255]$ represent the key-derived keystream:

$$\text{Encryption: } C_{x,y,c} = P_{x,y,c} \oplus K_{x,y,c}$$
$$\text{Decryption: } P_{x,y,c} = C_{x,y,c} \oplus K_{x,y,c}$$

Since XOR is self-inverting ($(A \oplus B) \oplus B = A$), applying the identical keystream restores the exact original pixel values.

### 3. Modular Arithmetic Shift (`swap`)
Pixel intensities are shifted using modular addition:

$$\text{Encryption: } C_{x,y,c} = (P_{x,y,c} + K_{x,y,c}) \pmod{256}$$
$$\text{Decryption: } P_{x,y,c} = (C_{x,y,c} - K_{x,y,c} + 256) \pmod{256}$$

Additionally, Red ($c=0$) and Blue ($c=2$) channels are swapped during encryption and un-swapped during decryption.

### 4. Spatial Pixel Position Shuffling (`shuffle`)
The 2D/3D image array of dimensions $H \times W$ with $N = H \cdot W$ pixels is flattened to a 1D sequence. A permutation sequence $\pi$ of length $N$ is generated using PRNG seed $S$:

$$\text{Encryption: } \text{Flat}_{\text{enc}}[i] = \text{Flat}_{\text{orig}}[\pi[i]]$$
$$\text{Decryption: } \text{Flat}_{\text{orig}}[i] = \text{Flat}_{\text{enc}}[\pi^{-1}[i]] \quad \text{where } \pi^{-1} = \text{argsort}(\pi)$$

---

## Installation & Setup

### Prerequisites
Ensure Python 3.8+ is installed on your system.

### Install Dependencies
Navigate into the project directory and install the required dependencies:

```bash
cd Prodigy_CS_02
pip install -r requirements.txt
```

---

## Usage Guide

### 1. Interactive Command Line Menu
Launch the interactive menu by executing `image_encryptor.py` without arguments:

```bash
python image_encryptor.py
```

Follow the terminal prompts to select operations, input image paths, secret keys, and modes.

---

### 2. Scriptable Command Line Arguments
Run encryption or decryption directly from the command line using arguments:

#### **Encrypt an Image**:
```bash
python image_encryptor.py -e -i sample.png -o encrypted.png -k "SecretPasscode123" -m combined
```

#### **Decrypt an Image**:
```bash
python image_encryptor.py -d -i encrypted.png -o decrypted.png -k "SecretPasscode123" -m combined
```

#### CLI Parameters Reference:

| Option | Long Flag | Description |
| :--- | :--- | :--- |
| `-e` | `--encrypt` | Flag to run encryption mode. |
| `-d` | `--decrypt` | Flag to run decryption mode. |
| `-i` | `--input` | Path to the target input image file. |
| `-o` | `--output` | Destination path for the processed output image file. |
| `-k` | `--key` | Secret key or passcode string. |
| `-m` | `--mode` | Manipulation mode: `combined` *(default)*, `xor`, `swap`, `shuffle`. |
| | `--gui` | Flag to launch the Tkinter Graphical User Interface. |

---

### 3. Graphical User Interface (GUI) Mode
To open the graphical interface:

```bash
python image_encryptor.py --gui
```

---

## Automated Unit Testing

Run the built-in unit test suite to verify 100% mathematical accuracy across all encryption modes and image color spaces:

```bash
python test_image_encryptor.py
```

---

## Project File Structure

```
Prodigy_CS_02/
├── image_encryptor.py      # Core encryption engine, CLI & GUI interface
├── test_image_encryptor.py # Automated unit test suite
├── requirements.txt        # Dependencies (Pillow, NumPy)
└── README.md               # Project documentation
```

---

## Security & Lossless Format Note

> [!IMPORTANT]
> **Lossless Image Storage**: Always store encrypted output images using lossless formats such as **PNG** or **BMP**. Lossy image formats like **JPEG** apply discrete cosine transform (DCT) compression that slightly alters pixel values. Because pixel manipulation requires exact bit-level preservation, lossy compression will corrupt the decryption process.

---

## Author

- **Kaustubh Bangar**
- Track: Cyber Security Internship at Prodigy InfoTech
