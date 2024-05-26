import customtkinter as cutk
from PIL import Image, ImageTk

def main():
    # Initialize the main window
    app = cutk.CTk()
    app.title("Emoji Display Example")
    app.geometry("600x400")
    
    # Create a frame to contain the label
    shell_frame = cutk.CTkFrame(master=app)
    shell_frame.pack(pady=20, padx=20, fill="both", expand=True)
    
    # Create a label with text
    shell_label = cutk.CTkLabel(
        master=shell_frame, 
        text="Enter your IP and Port PLS!!!", 
        font=("Arial", 20), 
        wraplength=500
    )
    shell_label.pack(pady=20, padx=20, side="left")
    
    # Load the emoji image
    emoji_image = Image.open("python_log.png")  # Replace with your emoji image path
    emoji_image = emoji_image.resize((30, 30), Image.LANCZOS)  # Resize the image if necessary
    emoji_photo = ImageTk.PhotoImage(emoji_image)
    
    # Create a label for the emoji image
    emoji_label = cutk.CTkLabel(master=shell_frame, text="", image=emoji_photo)
    emoji_label.pack(pady=20, padx=20, side="left")
    
    # Keep a reference to the image to prevent garbage collection
    emoji_label.image = emoji_photo
    
    # Run the application
    app.mainloop()

if __name__ == "__main__":
    main()
