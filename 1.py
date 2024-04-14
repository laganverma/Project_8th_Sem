import tkinter as tk
from tkinter import messagebox
from datetime import datetime
import threading
import time
import requests
import matplotlib.pyplot as plt
import random
import socket
import os
import psutil

# Define a class to manage user behavior simulation
class UserBehaviorSimulator:
    def __init__(self):
        self.login_attempts = 0
        self.failed_login_attempts = 0
        self.used_usernames = set()
        self.used_passwords = set()
        self.incidents = []

        # Data for visualization
        self.login_timestamps = []
        self.failed_login_timestamps = []

    def simulate_login(self):
        self.login_attempts += 1
        self.login_timestamps.append(datetime.now())

    def simulate_failed_login(self):
        self.failed_login_attempts += 1
        self.failed_login_timestamps.append(datetime.now())

    def record_credentials(self, username, password):
        self.used_usernames.add(username)
        self.used_passwords.add(password)

    def reset_login_attempts(self):
        self.login_attempts = 0
        self.failed_login_attempts = 0

    def generate_report(self):
        # Generate visualization before generating the report
        self.generate_visualization()

        # Save incident report
        report_filename = "incident_report.txt"
        with open(report_filename, "w") as report_file:
            report_file.write(f"Report generated at: {datetime.now()}\n")
            report_file.write(f"Total Login Attempts: {self.login_attempts}\n")
            report_file.write(f"Total Failed Login Attempts: {self.failed_login_attempts}\n")
            report_file.write("Used Usernames:\n")
            for username in self.used_usernames:
                report_file.write(f"- {username}\n")
            report_file.write("Used Passwords:\n")
            for password in self.used_passwords:
                report_file.write(f"- {password}\n")
            report_file.write("\nIncidents:\n")
            for incident in self.incidents:
                report_file.write(f"- {incident}\n")
        messagebox.showinfo("Report Generated", f"Report saved as {report_filename}")

    def generate_visualization(self):
        # Create a simple visualization using Matplotlib
        plt.figure(figsize=(10, 6))
        plt.plot(self.login_timestamps, label="Successful Logins", marker='o')
        plt.plot(self.failed_login_timestamps, label="Failed Logins", marker='x')
        plt.xlabel("Time")
        plt.ylabel("Login Attempts")
        plt.title("Login Activity Over Time")
        plt.legend()
        plt.grid(True)
        plt.xticks(rotation=45)
        plt.tight_layout()
        visualization_filename = "login_activity.png"
        plt.savefig(visualization_filename)  # Save the plot as an image
        plt.show()

    def add_incident(self, timestamp, ip_address, username, action, affected_user=None, response=None):
        incident_details = f"{timestamp} - IP: {ip_address}, Username: {username}, Action: {action}"
        if affected_user:
            incident_details += f", Affected User: {affected_user}"
        if response:
            incident_details += f", Response: {response}"
        self.incidents.append(incident_details)

    def lock_user_account(self, username):
        # Implement logic to lock the user account
        pass

    def alert_administrator(self, message):
        # Implement logic to send alerts to administrators
        pass

    def perform_auto_response(self, username):
        # Simulate automated response actions based on predefined rules
        self.lock_user_account(username)  # Lock the user account
        self.add_incident(datetime.now(), "IP Address", username, "Account Locked", affected_user=username, response="Automated response: User account locked")

        # Integrate with external tools (example: send alert via HTTP POST request)
        alert_data = {
            "timestamp": str(datetime.now()),
            "username": username,
            "action": "Account Locked",
            "message": "Automated response: User account locked due to suspicious activity"
        }
        response = requests.post("https://example.com/alert", json=alert_data)
        if response.status_code == 200:
            print("Alert sent successfully")
        else:
            print("Failed to send alert")

# Define a class for the login GUI
class LoginGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Login Simulation")
        self.root.geometry("300x250")

        self.user_simulator = UserBehaviorSimulator()
        self.logged_in = False

        self.label_login_attempts = tk.Label(root, text="Login Attempts: 0")
        self.label_login_attempts.pack()
        self.label_failed_attempts = tk.Label(root, text="Failed Login Attempts: 0")
        self.label_failed_attempts.pack()

        self.label_username = tk.Label(root, text="Username:")
        self.label_username.pack()
        self.entry_username = tk.Entry(root)
        self.entry_username.pack()

        self.label_password = tk.Label(root, text="Password:")
        self.label_password.pack()
        self.entry_password = tk.Entry(root, show="*")
        self.entry_password.pack()

        self.button_login = tk.Button(root, text="Login", command=self.login)
        self.button_login.pack()

        self.monitor_thread = threading.Thread(target=self.monitor_login_activity)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()

    # Function to handle login
    def login(self):
        username = self.entry_username.get()
        password = self.entry_password.get()

        credentials = read_credentials("passwords.txt")

        if credentials and username in credentials and credentials[username] == password:
            self.user_simulator.simulate_login()
            messagebox.showinfo("Login Successful", "Welcome!")
            self.user_simulator.reset_login_attempts()
            self.entry_username.delete(0, tk.END)
            self.entry_password.delete(0, tk.END)
            self.logged_in = True  # Set logged_in flag to True
        else:
            self.user_simulator.simulate_failed_login()
            messagebox.showerror("Login Failed", "Incorrect Username or Password!")
            self.user_simulator.record_credentials(username, password)
            if self.user_simulator.failed_login_attempts == 3:
                self.user_simulator.perform_auto_response(username)
                self.user_simulator.generate_report()  # Generate report on failed login attempts
                messagebox.showwarning("No More Attempts", "You have reached the maximum number of login attempts.")
                self.button_login.config(state=tk.DISABLED)

    # Function to monitor login activity
    def monitor_login_activity(self):
        while True:
            self.label_login_attempts.config(text=f"Login Attempts: {self.user_simulator.login_attempts}")
            self.label_failed_attempts.config(text=f"Failed Login Attempts: {self.user_simulator.failed_login_attempts}")
            time.sleep(1)

# Function to read credentials from a file
def read_credentials(file_path):
    credentials = {}
    try:
        with open("", "r") as file:
            for line in file:
                line = line.strip()  # Remove leading/trailing whitespace
                if line:  # Check if the line is not empty
                    parts = line.split(':')
                    if len(parts) == 2:  # Ensure there are exactly two parts (username and password)
                        username, password = parts
                        credentials[username] = password
                    else:
                        print(f"Ignore malformed line: {line}")
    except FileNotFoundError:
        print("Password file not found.")
    return credentials

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
