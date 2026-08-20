#!/usr/bin/env python3
"""
PRODIGY_CS_02: Pixel Manipulation for Image Encryption
Developed for Prodigy InfoTech Cyber Security Internship Track.

Author: Kaustubh Bangar
Language: Python 3
Dependencies: Pillow, NumPy
"""

import os
import sys
import argparse
import hashlib
from typing import Tuple, Optional
import numpy as np
from PIL import Image

# Terminal ANSI Color Formatting
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class ImageEncryptor:
    """Core image encryption and decryption engine using pixel manipulation."""

    @staticmethod
    def _derive_seed(key: str) -> int:
        """Derives a deterministic 64-bit integer seed from a string secret key using SHA-256."""
        sha256_hash = hashlib.sha256(key.encode('utf-8')).digest()
        # Convert first 8 bytes into a 64-bit integer
        return int.from_bytes(sha256_hash[:8], byteorder='big')

    @staticmethod
    def encrypt_xor(img_array: np.ndarray, key: str) -> np.ndarray:
        """
        Encrypts an image array using key-derived bitwise XOR operation.
        
        Args:
            img_array: NumPy array of shape (H, W, C) or (H, W) in uint8.
            key: Secret passcode string.
            
        Returns:
            Encrypted NumPy array in uint8.
        """
        seed = ImageEncryptor._derive_seed(key)
        rng = np.random.default_rng(seed)
        
        keystream = rng.integers(0, 256, size=img_array.shape, dtype=np.uint8)
        
        # Preserve alpha channel for RGBA images so output remains opaque/visible
        if img_array.ndim == 3 and img_array.shape[2] == 4:
            keystream[:, :, 3] = 0

        encrypted = np.bitwise_xor(img_array, keystream)
        return encrypted.astype(np.uint8)

    @staticmethod
    def decrypt_xor(img_array: np.ndarray, key: str) -> np.ndarray:
        """
        Decrypts an XOR-encrypted image array.
        XOR decryption is symmetric: (P ^ K) ^ K = P.
        """
        return ImageEncryptor.encrypt_xor(img_array, key)

    @staticmethod
    def encrypt_swap(img_array: np.ndarray, key: str) -> np.ndarray:
        """
        Encrypts an image by applying key-derived modular addition and channel swapping.
        
        Args:
            img_array: NumPy array in uint8.
            key: Secret passcode string.
            
        Returns:
            Encrypted NumPy array in uint8.
        """
        seed = ImageEncryptor._derive_seed(key)
        rng = np.random.default_rng(seed)
        
        shift = rng.integers(0, 256, size=img_array.shape, dtype=np.uint16)
        if img_array.ndim == 3 and img_array.shape[2] == 4:
            shift[:, :, 3] = 0

        shifted = (img_array.astype(np.uint16) + shift) % 256
        result = shifted.astype(np.uint8)

        # Swap Red (channel 0) and Blue (channel 2) for color images
        if result.ndim == 3 and result.shape[2] >= 3:
            result = result.copy()
            result[:, :, [0, 2]] = result[:, :, [2, 0]]

        return result

    @staticmethod
    def decrypt_swap(img_array: np.ndarray, key: str) -> np.ndarray:
        """
        Decrypts a swap/shift encrypted image array.
        Inverts channel swap first, then applies modular subtraction.
        """
        seed = ImageEncryptor._derive_seed(key)
        rng = np.random.default_rng(seed)
        
        result = img_array.copy()
        if result.ndim == 3 and result.shape[2] >= 3:
            result[:, :, [0, 2]] = result[:, :, [2, 0]]

        shift = rng.integers(0, 256, size=img_array.shape, dtype=np.uint16)
        if img_array.ndim == 3 and img_array.shape[2] == 4:
            shift[:, :, 3] = 0

        unshifted = (result.astype(np.uint16) - shift + 256) % 256
        return unshifted.astype(np.uint8)

    @staticmethod
    def encrypt_shuffle(img_array: np.ndarray, key: str) -> np.ndarray:
        """
        Encrypts an image by shuffling spatial pixel coordinates using a key-seeded PRNG permutation.
        
        Args:
            img_array: NumPy array of shape (H, W, C) or (H, W).
            key: Secret passcode string.
            
        Returns:
            Encrypted NumPy array with shuffled pixel positions.
        """
        seed = ImageEncryptor._derive_seed(key)
        rng = np.random.default_rng(seed)
        
        shape = img_array.shape
        num_pixels = shape[0] * shape[1]
        
        perm = rng.permutation(num_pixels)
        
        if img_array.ndim == 3:
            flat_img = img_array.reshape(num_pixels, shape[2])
            shuffled_flat = flat_img[perm]
            return shuffled_flat.reshape(shape)
        else:
            flat_img = img_array.reshape(num_pixels)
            shuffled_flat = flat_img[perm]
            return shuffled_flat.reshape(shape)

    @staticmethod
    def decrypt_shuffle(img_array: np.ndarray, key: str) -> np.ndarray:
        """
        Decrypts a shuffled image by applying inverse spatial coordinate permutation.
        """
        seed = ImageEncryptor._derive_seed(key)
        rng = np.random.default_rng(seed)
        
        shape = img_array.shape
        num_pixels = shape[0] * shape[1]
        
        perm = rng.permutation(num_pixels)
        inv_perm = np.argsort(perm)
        
        if img_array.ndim == 3:
            flat_img = img_array.reshape(num_pixels, shape[2])
            unshuffled_flat = flat_img[inv_perm]
            return unshuffled_flat.reshape(shape)
        else:
            flat_img = img_array.reshape(num_pixels)
            unshuffled_flat = flat_img[inv_perm]
            return unshuffled_flat.reshape(shape)

    @staticmethod
    def encrypt_combined(img_array: np.ndarray, key: str) -> np.ndarray:
        """Combines spatial pixel shuffling and bitwise XOR transformation."""
        shuffled = ImageEncryptor.encrypt_shuffle(img_array, key)
        encrypted = ImageEncryptor.encrypt_xor(shuffled, key)
        return encrypted

    @staticmethod
    def decrypt_combined(img_array: np.ndarray, key: str) -> np.ndarray:
        """Inverts XOR transformation first, then inverts spatial pixel shuffling."""
        un_xored = ImageEncryptor.decrypt_xor(img_array, key)
        decrypted = ImageEncryptor.decrypt_shuffle(un_xored, key)
        return decrypted


def process_image(input_path: str, output_path: str, key: str, mode: str, action: str) -> str:
    """
    Loads an image, performs encryption or decryption, and saves the output.
    
    Args:
        input_path: Path to source image file.
        output_path: Path to target destination image file.
        key: Secret passcode string.
        mode: Encryption operation ('xor', 'swap', 'shuffle', 'combined').
        action: Operation type ('encrypt' or 'decrypt').
        
    Returns:
        Absolute path of saved output image file.
    """
    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input image file not found: {input_path}")
        
    if not key:
        raise ValueError("Secret key cannot be empty.")
        
    # Open image with Pillow
    with Image.open(input_path) as img:
        img_format = img.format
        img_mode = img.mode
        img_array = np.array(img)

    # Lossless format enforcement check
    ext = os.path.splitext(output_path)[1].lower()
    if ext in ['.jpg', '.jpeg']:
        output_path = os.path.splitext(output_path)[0] + '.png'
        print(f"{Colors.WARNING}[!] Warning: JPEG compression is lossy and corrupts pixel decryption.{Colors.ENDC}")
        print(f"{Colors.WARNING}[!] Automatically redirected output to PNG format: {output_path}{Colors.ENDC}")

    mode_map = {
        'xor': (ImageEncryptor.encrypt_xor, ImageEncryptor.decrypt_xor),
        'swap': (ImageEncryptor.encrypt_swap, ImageEncryptor.decrypt_swap),
        'shuffle': (ImageEncryptor.encrypt_shuffle, ImageEncryptor.decrypt_shuffle),
        'combined': (ImageEncryptor.encrypt_combined, ImageEncryptor.decrypt_combined)
    }
    
    if mode.lower() not in mode_map:
        raise ValueError(f"Invalid mode '{mode}'. Choose from: {list(mode_map.keys())}")

    encrypt_func, decrypt_func = mode_map[mode.lower()]
    
    if action.lower() == 'encrypt':
        processed_array = encrypt_func(img_array, key)
    elif action.lower() == 'decrypt':
        processed_array = decrypt_func(img_array, key)
    else:
        raise ValueError(f"Invalid action '{action}'. Use 'encrypt' or 'decrypt'.")

    # Save processed image preserving original mode
    processed_img = Image.fromarray(processed_array)
    if processed_img.mode != img_mode:
        processed_img = processed_img.convert(img_mode)
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    processed_img.save(output_path, format='PNG' if ext not in ['.bmp'] else 'BMP')
    
    return os.path.abspath(output_path)


def launch_gui():
    """Launches lightweight Tkinter GUI window for interactive image processing."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
    except ImportError:
        print(f"{Colors.FAIL}[-] Tkinter module is not available in your Python installation.{Colors.ENDC}")
        return

    root = tk.Tk()
    root.title("Prodigy CS Task-02: Image Encryptor")
    root.geometry("520x420")
    root.resizable(False, False)

    # Style configuration
    style = ttk.Style()
    style.theme_use('clam')

    # Header Label
    header = tk.Label(
        root, 
        text="🔐 Pixel Manipulation Image Encryptor", 
        font=("Helvetica", 14, "bold"), 
        bg="#1e1e2e", 
        fg="#cdd6f4", 
        pady=12
    )
    header.pack(fill="x")

    frame = ttk.Frame(root, padding=20)
    frame.pack(fill="both", expand=True)

    # File Selection
    file_path_var = tk.StringVar()
    ttk.Label(frame, text="Input Image Path:", font=("Helvetica", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
    entry_file = ttk.Entry(frame, textvariable=file_path_var, width=38)
    entry_file.grid(row=1, column=0, columnspan=2, sticky="w", pady=5)

    def browse_file():
        path = filedialog.askopenfilename(
            title="Select Image File",
            filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.webp"), ("All Files", "*.*")]
        )
        if path:
            file_path_var.set(path)

    btn_browse = ttk.Button(frame, text="Browse...", command=browse_file)
    btn_browse.grid(row=1, column=2, padx=5, pady=5)

    # Secret Key
    key_var = tk.StringVar()
    ttk.Label(frame, text="Secret Passcode / Key:", font=("Helvetica", 10, "bold")).grid(row=2, column=0, sticky="w", pady=5)
    entry_key = ttk.Entry(frame, textvariable=key_var, show="*", width=38)
    entry_key.grid(row=3, column=0, columnspan=2, sticky="w", pady=5)

    # Mode Selection
    mode_var = tk.StringVar(value="combined")
    ttk.Label(frame, text="Operation Mode:", font=("Helvetica", 10, "bold")).grid(row=4, column=0, sticky="w", pady=5)
    combo_mode = ttk.Combobox(frame, textvariable=mode_var, values=["combined", "xor", "swap", "shuffle"], state="readonly", width=15)
    combo_mode.grid(row=4, column=1, sticky="w", pady=5)

    # Status Label
    status_var = tk.StringVar(value="Ready")
    lbl_status = ttk.Label(frame, textvariable=status_var, font=("Helvetica", 9, "italic"), foreground="gray")
    lbl_status.grid(row=6, column=0, columnspan=3, pady=15)

    def execute_action(action_type: str):
        in_path = file_path_var.get().strip()
        key = key_var.get().strip()
        mode = mode_var.get().strip()

        if not in_path or not os.path.exists(in_path):
            messagebox.showerror("Error", "Please select a valid input image file.")
            return

        if not key:
            messagebox.showerror("Error", "Please enter a secret key.")
            return

        ext = os.path.splitext(in_path)[1]
        default_out = f"{os.path.splitext(in_path)[0]}_{action_type}_{mode}.png"
        out_path = filedialog.asksaveasfilename(
            title=f"Save {action_type.capitalize()}ed Image",
            initialfile=os.path.basename(default_out),
            defaultextension=".png",
            filetypes=[("PNG Image", "*.png"), ("BMP Image", "*.bmp")]
        )

        if not out_path:
            return

        try:
            saved_path = process_image(in_path, out_path, key, mode, action_type)
            status_var.set(f"Successfully saved to {os.path.basename(saved_path)}")
            messagebox.showinfo("Success", f"Image successfully {action_type}ed!\nSaved to:\n{saved_path}")
        except Exception as e:
            status_var.set("Error occurred during processing.")
            messagebox.showerror("Processing Error", str(e))

    btn_frame = ttk.Frame(frame)
    btn_frame.grid(row=5, column=0, columnspan=3, pady=15)

    btn_encrypt = tk.Button(
        btn_frame, 
        text="🔒 Encrypt Image", 
        bg="#27ae60", 
        fg="white", 
        font=("Helvetica", 10, "bold"),
        padx=15, 
        pady=8,
        relief="flat",
        command=lambda: execute_action("encrypt")
    )
    btn_encrypt.pack(side="left", padx=10)

    btn_decrypt = tk.Button(
        btn_frame, 
        text="🔓 Decrypt Image", 
        bg="#2980b9", 
        fg="white", 
        font=("Helvetica", 10, "bold"),
        padx=15, 
        pady=8,
        relief="flat",
        command=lambda: execute_action("decrypt")
    )
    btn_decrypt.pack(side="left", padx=10)

    root.mainloop()


def interactive_cli():
    """Prints colored banner and launches interactive command-line interface."""
    banner = f"""
{Colors.OKCYAN}{Colors.BOLD}====================================================================
 🔐 PRODIGY_CS_02: Pixel Manipulation Image Encryption Tool
  Track: Cyber Security Internship | Developed by: Kaustubh Bangar
===================================================================={Colors.ENDC}
"""
    print(banner)

    while True:
        print(f"\n{Colors.BOLD}Select an Option:{Colors.ENDC}")
        print(f" {Colors.OKGREEN}[1]{Colors.ENDC} Encrypt an Image")
        print(f" {Colors.OKGREEN}[2]{Colors.ENDC} Decrypt an Image")
        print(f" {Colors.OKGREEN}[3]{Colors.ENDC} Launch Graphical UI (GUI Mode)")
        print(f" {Colors.OKGREEN}[4]{Colors.ENDC} Exit Application")

        choice = input(f"\n{Colors.BOLD}Enter choice (1-4): {Colors.ENDC}").strip()

        if choice == '4':
            print(f"\n{Colors.OKBLUE}Exiting application. Goodbye!{Colors.ENDC}")
            sys.exit(0)

        if choice == '3':
            print(f"{Colors.OKCYAN}Launching Tkinter GUI...{Colors.ENDC}")
            launch_gui()
            continue

        if choice not in ['1', '2']:
            print(f"{Colors.FAIL}[!] Invalid selection. Please enter 1, 2, 3, or 4.{Colors.ENDC}")
            continue

        action = 'encrypt' if choice == '1' else 'decrypt'
        
        # Prompts
        input_path = input(f"{Colors.BOLD}Enter path to input image: {Colors.ENDC}").strip().strip('"').strip("'")
        if not os.path.exists(input_path):
            print(f"{Colors.FAIL}[-] File not found: {input_path}{Colors.ENDC}")
            continue

        key = input(f"{Colors.BOLD}Enter secret passcode / key: {Colors.ENDC}").strip()
        if not key:
            print(f"{Colors.FAIL}[-] Secret key cannot be empty.{Colors.ENDC}")
            continue

        print(f"\n{Colors.BOLD}Select Encryption Mode:{Colors.ENDC}")
        print(" [1] Combined (Pixel Shuffle + XOR - Recommended)")
        print(" [2] XOR Bitwise Transformation")
        print(" [3] Swap & Modular Arithmetic Shift")
        print(" [4] Spatial Pixel Position Shuffling")
        
        mode_choice = input(f"{Colors.BOLD}Choose mode (1-4, default=1): {Colors.ENDC}").strip()
        mode_map = {'1': 'combined', '2': 'xor', '3': 'swap', '4': 'shuffle', '': 'combined'}
        mode = mode_map.get(mode_choice, 'combined')

        default_out = f"{os.path.splitext(input_path)[0]}_{action}_{mode}.png"
        output_path = input(f"{Colors.BOLD}Enter output image path (default: {os.path.basename(default_out)}): {Colors.ENDC}").strip().strip('"').strip("'")
        if not output_path:
            output_path = default_out

        try:
            print(f"\n{Colors.OKCYAN}[*] Processing image with mode '{mode}'...{Colors.ENDC}")
            result_path = process_image(input_path, output_path, key, mode, action)
            print(f"{Colors.OKGREEN}{Colors.BOLD}[+] SUCCESS! Image saved to: {result_path}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error processing image: {e}{Colors.ENDC}")


def main():
    parser = argparse.ArgumentParser(
        description="PRODIGY_CS_02: Image Encryption Tool using Pixel Manipulation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python image_encryptor.py -e -i secret.png -o encrypted.png -k "MySecretPasscode123" -m combined
  python image_encryptor.py -d -i encrypted.png -o decrypted.png -k "MySecretPasscode123" -m combined
  python image_encryptor.py --gui
"""
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument('-e', '--encrypt', action='store_true', help='Encrypt the specified image file.')
    group.add_argument('-d', '--decrypt', action='store_true', help='Decrypt the specified image file.')
    group.add_argument('--gui', action='store_true', help='Launch the graphical user interface.')

    parser.add_argument('-i', '--input', type=str, help='Path to the input image file.')
    parser.add_argument('-o', '--output', type=str, help='Path for saving the output image file.')
    parser.add_argument('-k', '--key', type=str, help='Secret key or passcode for encryption/decryption.')
    parser.add_argument(
        '-m', '--mode', 
        type=str, 
        choices=['xor', 'swap', 'shuffle', 'combined'], 
        default='combined',
        help='Pixel manipulation operation mode (default: combined).'
    )

    args = parser.parse_args()

    # If GUI flag passed, launch GUI directly
    if args.gui:
        launch_gui()
        return

    # If CLI flags passed for batch execution
    if args.encrypt or args.decrypt:
        action = 'encrypt' if args.encrypt else 'decrypt'
        if not args.input:
            print(f"{Colors.FAIL}[-] Missing required argument: --input / -i{Colors.ENDC}")
            sys.exit(1)
        if not args.key:
            print(f"{Colors.FAIL}[-] Missing required argument: --key / -k{Colors.ENDC}")
            sys.exit(1)
            
        output_path = args.output
        if not output_path:
            output_path = f"{os.path.splitext(args.input)[0]}_{action}_{args.mode}.png"

        try:
            res = process_image(args.input, output_path, args.key, args.mode, action)
            print(f"{Colors.OKGREEN}[+] Task completed successfully! Output saved to: {res}{Colors.ENDC}")
        except Exception as e:
            print(f"{Colors.FAIL}[-] Error: {e}{Colors.ENDC}")
            sys.exit(1)
        return

    # Default to interactive CLI menu if no CLI flags provided
    interactive_cli()


if __name__ == '__main__':
    main()
