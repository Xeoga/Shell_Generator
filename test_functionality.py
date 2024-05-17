import customtkinter as cutk
import tkinter as tk

def copy_to_clipboard():
    master.clipboard_clear()
    master.clipboard_append(shell_label.cget("text"))
    master.update()  # necessary to update the clipboard contents

master = cutk.CTk()
shell_frame = cutk.CTkFrame(master)
shell_frame.pack(pady=20, padx=20)

shell_label = cutk.CTkLabel(shell_frame, text="Enter your IP and Port PLS!!! 😄", font=("Arial", 15))
shell_label.pack(pady=10)

copy_button = cutk.CTkButton(shell_frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.pack(pady=10)

master.mainloop()