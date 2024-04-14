import requests

# Your IP address
your_ip_address = "192.168.29.135"

# URL to check network connectivity
url = f"http://{your_ip_address}/check_network"

# Function to record unauthorized access
def record_access(ip_address):
    with open("unauthorized_access.log", "a") as log_file:
        log_file.write(f"Unauthorized access from IP address: {ip_address}\n")

try:
    response = requests.get(url)
    if response.status_code == 200:
        print("Network connection verified. File is being accessed on the right network.")
    else:
        print("Failed to verify network connection. Please check your internet connection.")
except requests.ConnectionError:
    user_ip_address = requests.get('https://api64.ipify.org').text
    if user_ip_address != your_ip_address:
        record_access(user_ip_address)
        print(f"Unauthorized access from IP address: {user_ip_address}")
    else:
        print("Failed to establish a connection. Please check your internet connection.")
