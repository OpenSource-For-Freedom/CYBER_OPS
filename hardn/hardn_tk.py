import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk

class Hard3nGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Hardn System")
        self.root.geometry("400x400")

        # Configure the main frame
        self.frame = tk.Frame(self.root, bg="#2b2b2b")
        self.frame.pack(fill=tk.BOTH, expand=True)

        # Add Debian logo
        self.logo_image = Image.open("/usr/share/home/tim/downloads/debian-logo.png")
        self.logo_image = self.logo_image.resize((48, 48), Image.ANTIALIAS)
        self.logo_photo = ImageTk.PhotoImage(self.logo_image)

        self.logo_label = tk.Label(self.frame, image=self.logo_photo, bg="#2b2b2b")
        self.logo_label.pack(pady=10)

        # Add HARD3N title
        self.title_label = tk.Label(
            self.frame, text="HARDN", bg="#2b2b2b", fg="White",
            font=("Helvetica", 24, "bold")
        )
        self.title_label.pack(pady=10)

        # buttons
        self.yes_button = tk.Button(
            self.frame, text="YES", bg="red", fg="black", font=("Helvetica", 16, "bold"),
            command=self.on_yes
        )
        self.yes_button.pack(pady=20, ipadx=20, ipady=10)

        self.no_button = tk.Button(
            self.frame, text="NO", bg="red", fg="black", font=("Helvetica", 16, "bold"),
            command=self.on_no
        )
        self.no_button.pack(pady=10, ipadx=20, ipady=10)

    def on_yes(self):
        """Handler for the YES button."""
        response = messagebox.askyesno(
            "Confirm", "Are you sure you want to execute the Hard3n Qube script?"
        )
        if response:
            self.execute_qube_script()

    def execute_qube_script(self):
        """Logic to execute the Hard3n Qube script."""
        try:
            import subprocess
            subprocess.run("python3 hardn_qube.py", shell=True, check=True)
            messagebox.showinfo("Success", "Hardn Qube executed successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to execute Hardn Qube: {e}")

    def on_no(self):
        """Handler for the NO button."""
        self.root.destroy()

    def run(self):
        """Run the Tkinter event loop."""
        self.root.mainloop()

# Ex Hard3nGUI
if __name__ == "__main__":
    gui = HardnGUI()
    gui.run()
