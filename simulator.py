import tkinter as tk
from tkinter import font

# Function to start simulation
def start_simulation():
    # Add code here to start your simulation
    print("Simulation started!")

# Create main window
root = tk.Tk()
root.title("Welcome to Simulation")

# Set window size and position
window_width = 600
window_height = 400
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
x = (screen_width / 2) - (window_width / 2)
y = (screen_height / 2) - (window_height / 2)
root.geometry(f"{window_width}x{window_height}+{int(x)}+{int(y)}")

# Set background color
root.configure(bg="#f0f0f0")

# Create welcome label with a quote
welcome_quote = tk.Label(root, text="Welcome to Our Simulation", font=("Helvetica", 24), bg="#f0f0f0")
welcome_quote.pack(pady=20)

# Create information labels
info_label1 = tk.Label(root, text="Explore the wonders of simulation!", font=("Helvetica", 16), bg="#f0f0f0")
info_label1.pack()
info_label2 = tk.Label(root, text="Simulate anything you can imagine.", font=("Helvetica", 16), bg="#f0f0f0")
info_label2.pack()
info_label3 = tk.Label(root, text="Have fun and learn along the way!", font=("Helvetica", 16), bg="#f0f0f0")
info_label3.pack(pady=20)

# Create start button
start_button = tk.Button(root, text="Start Simulation", font=("Helvetica", 16), bg="#4CAF50", fg="white", command=start_simulation)
start_button.pack(pady=20)

# Run the main loop
root.mainloop()