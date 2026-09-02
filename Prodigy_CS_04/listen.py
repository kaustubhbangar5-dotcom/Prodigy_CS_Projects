from pynput.mouse import Listener

def writetofile(x, y):
    print(f"Position of current mouse: ({x}, {y})")

if __name__ == "__main__":
    print("[INFO] Listening to mouse movements. Move your mouse or press Ctrl+C in terminal to stop.")
    try:
        with Listener(on_move=writetofile) as listener:
            listener.join()
    except KeyboardInterrupt:
        print("\n[INFO] Stopped mouse listener.")