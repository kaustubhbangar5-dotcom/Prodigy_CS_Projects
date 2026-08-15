"""
PRODIGY_CS_01: Caesar Cipher Implementation
Author: Kaustubh Bangar
Track: Cyber Security (CS) - Task 01
Description: A Python program to encrypt and decrypt text using the Caesar Cipher algorithm.
"""

def caesar_cipher(text: str, shift: int) -> str:
    """
    Encrypts or decrypts text using the Caesar Cipher algorithm.
    
    :param text: The input string (plaintext or ciphertext).
    :param shift: The key shift value (positive for encrypting, negative for decrypting).
    :return: Transformed string preserving original casing and non-alphabetic characters.
    """
    result = ""

    for char in text:
        if char.isupper():
            base = ord('A')
            # Convert ASCII to 0-25 alphabet index, apply shift modulo 26, convert back to ASCII
            new_position = (ord(char) - base + shift) % 26
            result += chr(base + new_position)
        elif char.islower():
            base = ord('a')
            # Convert ASCII to 0-25 alphabet index, apply shift modulo 26, convert back to ASCII
            new_position = (ord(char) - base + shift) % 26
            result += chr(base + new_position)
        else:
            # Leave numbers, spaces, punctuation, and special characters unchanged
            result += char

    return result


def get_integer_input(prompt: str) -> int:
    """Safely prompts the user for an integer input with error validation."""
    while True:
        try:
            return int(input(prompt))
        except ValueError:
            print("\n[!] Invalid input! Please enter a valid integer for the shift key.\n")


def main():
    """Main interactive execution loop for the Caesar Cipher application."""
    print("=" * 55)
    print("        PRODIGY INFOTECH - CYBER SECURITY TASK 01")
    print("                 CAESAR CIPHER TOOL")
    print("=" * 55)

    while True:
        print("\nSelect an Operation:")
        print("  [1] Encrypt Message")
        print("  [2] Decrypt Message")
        print("  [3] Exit")

        choice = input("\nEnter your choice (1/2/3): ").strip()

        if choice == "1":
            print("\n--- ENCRYPTION MODE ---")
            message = input("Enter the plaintext message: ")
            shift = get_integer_input("Enter shift value (key): ")

            encrypted_text = caesar_cipher(message, shift)
            print("\n" + "-" * 40)
            print(f"Original Text  : {message}")
            print(f"Shift Key      : {shift}")
            print(f"Encrypted Text : {encrypted_text}")
            print("-" * 40)

        elif choice == "2":
            print("\n--- DECRYPTION MODE ---")
            ciphertext = input("Enter the encrypted message: ")
            shift = get_integer_input("Enter shift value (key): ")

            # Decryption is encryption with negative shift
            decrypted_text = caesar_cipher(ciphertext, -shift)
            print("\n" + "-" * 40)
            print(f"Ciphertext     : {ciphertext}")
            print(f"Shift Key      : {shift}")
            print(f"Decrypted Text : {decrypted_text}")
            print("-" * 40)

        elif choice == "3":
            print("\nThank you for using the Caesar Cipher Tool! Exiting program...\n")
            break

        else:
            print("\n[!] Invalid selection. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
