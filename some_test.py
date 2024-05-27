import tkinter as tk

root = tk.Tk()

frame = tk.Frame(root)
frame.grid(row=0, column=0, padx=10, pady=10)

# Etichetă cu un text lung
label = tk.Label(frame, text="Acesta este un text lung care ar putea să se extindă foarte mult dacă nu este limitat de wraplength și ancorat.")
label.grid(row=0, column=0, padx=10, pady=10, sticky="w")  # Ancorează eticheta la stânga (west)

# Configurare pentru a împiedica extinderea coloanei
frame.grid_columnconfigure(0, weight=0)

root.mainloop()
