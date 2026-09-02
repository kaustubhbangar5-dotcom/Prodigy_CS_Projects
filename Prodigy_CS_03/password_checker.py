#!/usr/bin/env python3
"""
PRODIGY_CS_03: Password Complexity Checker
Developed for Prodigy InfoTech Cyber Security Internship Track.

Author: Kaustubh Bangar
Language: Python 3
Dependencies: Built-in Standard Library (re, math, secrets, tkinter, argparse)
"""

import sys
import os
import re
import math
import secrets
import string
import argparse
from typing import Dict, List, Tuple, Any

# Common weak passwords list for dictionary check
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567", "1234",
    "qwerty", "111111", "123123", "abc123", "password1", "admin", "welcome",
    "monkey", "dragon", "master", "sunshine", "letmein", "princess", "football",
    "shadow", "login", "guest", "pass123", "iloveyou", "trustno1", "operator"
}

class PasswordChecker:
    """Evaluates password complexity, calculates entropy, and generates security feedback."""

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculates password entropy in bits: E = length * log2(pool_size)."""
        if not password:
            return 0.0

        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += 26
        if re.search(r'[A-Z]', password):
            pool_size += 26
        if re.search(r'[0-9]', password):
            pool_size += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += 32  # Standard printable special symbols

        if pool_size == 0:
            return 0.0

        return len(password) * math.log2(pool_size)

    @classmethod
    def evaluate(cls, password: str) -> Dict[str, Any]:
        """Evaluates a password against security criteria and returns detailed analysis."""
        length = len(password)
        has_lower = bool(re.search(r'[a-z]', password))
        has_upper = bool(re.search(r'[A-Z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_special = bool(re.search(r'[^a-zA-Z0-9]', password))
        is_common = password.lower() in COMMON_PASSWORDS

        # Base score calculation (0 - 100)
        score = 0
        feedback: List[str] = []
        strengths: List[str] = []

        # Length Scoring
        if length >= 16:
            score += 35
            strengths.append("Excellent length (16+ characters)")
        elif length >= 12:
            score += 25
            strengths.append("Strong length (12-15 characters)")
        elif length >= 8:
            score += 15
            strengths.append("Moderate length (8-11 characters)")
        else:
            feedback.append("Increase length to at least 12 characters.")

        # Character Diversity Scoring
        if has_lower:
            score += 15
            strengths.append("Contains lowercase letters")
        else:
            feedback.append("Add lowercase letters (a-z).")

        if has_upper:
            score += 15
            strengths.append("Contains uppercase letters")
        else:
            feedback.append("Add uppercase letters (A-Z).")

        if has_digit:
            score += 15
            strengths.append("Contains numeric digits")
        else:
            feedback.append("Add numeric digits (0-9).")

        if has_special:
            score += 20
            strengths.append("Contains special characters (!@#$%^&*)")
        else:
            feedback.append("Add special characters (e.g. !@#$%^&*).")

        # Penalty for common weak passwords
        if is_common:
            score = min(score, 10)
            feedback.insert(0, "[CRITICAL] Password is a widely known weak dictionary password!")

        # Cap score between 0 and 100
        score = max(0, min(100, score))

        # Entropy calculation
        entropy = cls.calculate_entropy(password)

        # Strength Rating Classification
        if is_common or score <= 20:
            rating = "Very Weak"
            color = "Red"
        elif score <= 40:
            rating = "Weak"
            color = "Orange"
        elif score <= 60:
            rating = "Moderate"
            color = "Yellow"
        elif score <= 80:
            rating = "Strong"
            color = "Light Green"
        else:
            rating = "Very Strong"
            color = "Bright Green"

        # Estimated time to crack at 10^10 guesses/sec (GPU array cluster)
        guesses = (2 ** entropy) if entropy > 0 else 0
        crack_time_sec = guesses / (10 ** 10)
        crack_time_str = cls._format_crack_time(crack_time_sec)

        return {
            "password": password,
            "length": length,
            "score": score,
            "rating": rating,
            "color": color,
            "entropy": round(entropy, 2),
            "crack_time": crack_time_str,
            "has_lower": has_lower,
            "has_upper": has_upper,
            "has_digit": has_digit,
            "has_special": has_special,
            "is_common": is_common,
            "strengths": strengths,
            "feedback": feedback
        }

    @staticmethod
    def _format_crack_time(seconds: float) -> str:
        """Formats crack time in seconds to human readable units."""
        if seconds <= 0:
            return "Instant"
        elif seconds < 1:
            return "Less than a second"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds // 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds // 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds // 86400)} days"
        elif seconds < 31536000 * 1000:
            return f"{int(seconds // 31536000)} years"
        else:
            return "Centuries / Trillions of years"

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generates a cryptographically secure random password."""
        length = max(12, length)
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        all_chars = lowercase + uppercase + digits + symbols

        # Ensure at least one character from each required set
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(symbols)
        ]

        # Fill remaining characters randomly
        for _ in range(length - 4):
            password_chars.append(secrets.choice(all_chars))

        # Shuffle using secrets PRNG
        for i in range(len(password_chars) - 1, 0, -1):
            j = secrets.randbelow(i + 1)
            password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

        return "".join(password_chars)


def run_cli_interactive():
    """Runs interactive CLI loop."""
    print("=" * 65)
    print("        PRODIGY INFOTECH - CYBER SECURITY TASK 03")
    print("               PASSWORD COMPLEXITY CHECKER")
    print("=" * 65)

    checker = PasswordChecker()

    while True:
        print("\nSelect an Option:")
        print("  [1] Assess Password Strength")
        print("  [2] Generate Secure Password")
        print("  [3] Launch Graphical Interface (GUI)")
        print("  [4] Exit")

        choice = input("\nEnter choice (1/2/3/4): ").strip()

        if choice == "1":
            pwd = input("\nEnter password to evaluate: ").strip()
            if not pwd:
                print("[!] Password cannot be empty.")
                continue

            result = checker.evaluate(pwd)
            print("\n" + "-" * 50)
            print(f"Password Evaluated : {'*' * len(pwd)} ({pwd})")
            print(f"Overall Rating     : [{result['rating'].upper()}] (Score: {result['score']}/100)")
            print(f"Entropy Strength   : {result['entropy']} bits")
            print(f"Est. Crack Time    : {result['crack_time']}")
            print("-" * 50)
            print("Met Criteria:")
            for s in result['strengths']:
                print(f"  [+] {s}")

            if result['feedback']:
                print("\nImprovement Recommendations:")
                for f in result['feedback']:
                    print(f"  [-] {f}")
            print("-" * 50)

        elif choice == "2":
            try:
                len_str = input("Enter password length (default 16): ").strip()
                length = int(len_str) if len_str else 16
            except ValueError:
                length = 16

            new_pwd = checker.generate_secure_password(length)
            res = checker.evaluate(new_pwd)
            print("\n" + "-" * 50)
            print(f"Generated Password : {new_pwd}")
            print(f"Strength Rating    : {res['rating']} ({res['entropy']} bits entropy)")
            print("-" * 50)

        elif choice == "3":
            launch_gui()
            break

        elif choice == "4":
            print("\nExiting Password Complexity Checker. Stay Secure!\n")
            break

        else:
            print("[!] Invalid selection. Please enter 1, 2, 3, or 4.")


def launch_gui():
    """Launches Tkinter Graphical User Interface."""
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox
    except ImportError:
        print("[!] Tkinter module is not available in this Python environment.")
        return

    root = tk.Tk()
    root.title("PRODIGY_CS_03 - Password Complexity Checker")
    root.geometry("620x650")
    root.resizable(False, False)

    # Style configuration
    style = ttk.Style()
    style.theme_use('clam')

    # Header Title
    title_label = tk.Label(
        root, 
        text="Password Complexity Checker", 
        font=("Helvetica", 18, "bold"), 
        fg="#1E3A8A"
    )
    title_label.pack(pady=15)

    # Input Frame
    input_frame = tk.Frame(root)
    input_frame.pack(pady=10, fill="x", padx=20)

    pwd_label = tk.Label(input_frame, text="Enter Password:", font=("Helvetica", 11, "bold"))
    pwd_label.pack(anchor="w")

    pwd_entry = tk.Entry(input_frame, font=("Consolas", 13), show="*")
    pwd_entry.pack(fill="x", pady=5)

    # Checkbox toggle show password
    show_var = tk.BooleanVar()

    def toggle_show():
        pwd_entry.config(show="" if show_var.get() else "*")

    show_cb = tk.Checkbutton(input_frame, text="Show Password", variable=show_var, command=toggle_show)
    show_cb.pack(anchor="w")

    # Progress bar & Rating
    score_frame = tk.Frame(root)
    score_frame.pack(pady=15, fill="x", padx=20)

    rating_label = tk.Label(score_frame, text="Strength: Enter password", font=("Helvetica", 12, "bold"))
    rating_label.pack(anchor="w")

    progress = ttk.Progressbar(score_frame, orient="horizontal", length=580, mode="determinate")
    progress.pack(pady=8)

    info_label = tk.Label(score_frame, text="Entropy: 0.0 bits | Est. Crack Time: N/A", font=("Helvetica", 10))
    info_label.pack(anchor="w")

    # Feedback Text Box
    feedback_frame = tk.LabelFrame(root, text=" Detailed Security Analysis & Recommendations ", font=("Helvetica", 10, "bold"))
    feedback_frame.pack(pady=10, fill="both", expand=True, padx=20)

    feedback_text = tk.Text(feedback_frame, font=("Helvetica", 10), wrap="word", height=10)
    feedback_text.pack(fill="both", expand=True, padx=5, pady=5)

    def analyze_password(*args):
        password = pwd_entry.get()
        if not password:
            progress['value'] = 0
            rating_label.config(text="Strength: Enter password", fg="black")
            info_label.config(text="Entropy: 0.0 bits | Est. Crack Time: N/A")
            feedback_text.delete("1.0", tk.END)
            return

        res = PasswordChecker.evaluate(password)
        progress['value'] = res['score']

        color_map = {
            "Very Weak": "#DC2626",
            "Weak": "#EA580C",
            "Moderate": "#D97706",
            "Strong": "#16A34A",
            "Very Strong": "#059669"
        }
        fg_color = color_map.get(res['rating'], "black")

        rating_label.config(
            text=f"Strength: {res['rating'].upper()} ({res['score']}/100)",
            fg=fg_color
        )
        info_label.config(
            text=f"Entropy: {res['entropy']} bits | Est. Crack Time: {res['crack_time']}"
        )

        feedback_text.delete("1.0", tk.END)
        feedback_text.insert(tk.END, "MET CRITERIA:\n")
        for s in res['strengths']:
            feedback_text.insert(tk.END, f"  • {s}\n")

        if res['feedback']:
            feedback_text.insert(tk.END, "\nIMPROVEMENT SUGGESTIONS:\n")
            for f in res['feedback']:
                feedback_text.insert(tk.END, f"  • {f}\n")

    pwd_entry.bind("<KeyRelease>", analyze_password)

    # Button Frame
    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=15)

    def gen_pwd():
        new_pwd = PasswordChecker.generate_secure_password(16)
        pwd_entry.delete(0, tk.END)
        pwd_entry.insert(0, new_pwd)
        analyze_password()

    gen_btn = tk.Button(
        btn_frame, 
        text="Generate Secure Password", 
        font=("Helvetica", 10, "bold"), 
        bg="#2563EB", 
        fg="white", 
        command=gen_pwd,
        padx=15, 
        pady=5
    )
    gen_btn.pack(side="left", padx=10)

    root.mainloop()


def main():
    parser = argparse.ArgumentParser(description="PRODIGY_CS_03: Password Complexity Checker")
    parser.add_argument("-p", "--password", type=str, help="Password string to assess.")
    parser.add_argument("-g", "--generate", action="store_true", help="Generate a secure random password.")
    parser.add_argument("-l", "--length", type=int, default=16, help="Length for generated password (default 16).")
    parser.add_argument("--gui", action="store_true", help="Launch Tkinter Graphical User Interface.")

    args = parser.parse_args()

    if args.gui:
        launch_gui()
    elif args.password:
        res = PasswordChecker.evaluate(args.password)
        print(f"Password    : {args.password}")
        print(f"Rating      : {res['rating']} ({res['score']}/100)")
        print(f"Entropy     : {res['entropy']} bits")
        print(f"Crack Time  : {res['crack_time']}")
        print("Strengths   :", ", ".join(res['strengths']))
        if res['feedback']:
            print("Suggestions :", "; ".join(res['feedback']))
    elif args.generate:
        pwd = PasswordChecker.generate_secure_password(args.length)
        res = PasswordChecker.evaluate(pwd)
        print(f"Generated Password : {pwd}")
        print(f"Entropy            : {res['entropy']} bits ({res['rating']})")
    else:
        run_cli_interactive()


if __name__ == "__main__":
    main()
