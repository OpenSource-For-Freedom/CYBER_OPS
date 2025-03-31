import subprocess
import tkinter as tk
from tkinter import scrolledtext
import threading


def run_bash_script(script_path, log_path):
    with open(log_path, "w") as log_file:
        process = subprocess.Popen(['bash', script_path], stdout=log_file, stderr=log_file)
        process.wait()


def update_log_display(log_path, text_widget):
    with open(log_path, "r") as log_file:
        log_content = log_file.read()
    text_widget.config(state=tk.NORMAL)
    text_widget.delete(1.0, tk.END)
    text_widget.insert(tk.INSERT, log_content)
    text_widget.config(state=tk.DISABLED)


def run_and_display_logs(script_path, log_path, text_widget):
    threading.Thread(target=run_bash_script, args=(script_path, log_path)).start()
    threading.Thread(target=update_log_display, args=(log_path, text_widget)).start()


def create_gui(script_path, log_path):
    root = tk.Tk()
    root.title("Monitor Logs")

    frame = tk.Frame(root)
    frame.pack(padx=10, pady=10)

    text_widget = scrolledtext.ScrolledText(frame, width=80, height=20, state=tk.DISABLED)
    text_widget.pack(padx=10, pady=10)

    button = tk.Button(frame, text="Run Monitors", command=lambda: run_and_display_logs(script_path, log_path, text_widget))
    button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    script_path = "/path/to/run_monitors.sh"
    log_path = "/path/to/monitor.log"
    create_gui(script_path, log_path)