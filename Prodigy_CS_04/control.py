from pynput.mouse import Controller as MouseController
from pynput.keyboard import Controller as KeyboardController
import time

# Left to right (x), top to bottom (y)
# From top-left of the screen, (0, 0) is the top-left corner
def controlMouse():
    mouse = MouseController()
    # Move mouse to coordinates (500, 200)
    mouse.position = (500, 200)
    print(f"[INFO] Current mouse position: {mouse.position}")

def controlKeyboard():
    keyboard = KeyboardController()
    time.sleep(1)
    # Type text automatically
    keyboard.type("I am freaking awesome!")
    print("[INFO] Text typed successfully.")

if __name__ == "__main__":
    # Test controlling mouse:
    controlMouse()

    # Test controlling keyboard:
    controlKeyboard()

# 1. Controlling your mouse
# 2. Listening to your mouse
# 3. Controlling your keyboard
# 4. Listening to your keyboard - Used in our keylogger (main.py)