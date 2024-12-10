import tkinter as tk
from gui import SecureMessengerGUI

def main():
    root = tk.Tk()
    app = SecureMessengerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
