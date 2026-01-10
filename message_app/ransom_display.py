import tkinter as tk
from tkinter import messagebox

# Function to run when button is clicked
def on_button_click():
    messagebox.showinfo("Hello!", "You clicked the button!")

# Create main window
root = tk.Tk()
root.title("Simple Window")
root.geometry("300x150")  # Width x Height

# Add a label (message)
label = tk.Label(root, text="This is a simple message.", font=("Arial", 12))
label.pack(pady=20)  # Add some padding

# Add a button
button = tk.Button(root, text="Click Me", command=on_button_click)
button.pack()

# Start the GUI loop
root.mainloop()
