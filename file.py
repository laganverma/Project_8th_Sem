import pyshark

# File path to monitor
file_path = "C:/Users/lagan/OneDrive/Desktop/1.txt"

# Log file path
log_file_path = "file_access.log"

# Packet capture loop
cap = pyshark.LiveCapture(interface='Ethernet1')
for packet in cap.sniff_continuously():
    try:
        ip_src = packet.ip.src
        ip_dst = packet.ip.dst
        if file_path in str(packet) and ip_dst != "your_IP_address":
            log_entry = f"File {file_path} accessed from IP address {ip_src}\n"
            with open(log_file_path, "a") as log_file:
                log_file.write(log_entry)
            print(log_entry, end="")
    except AttributeError:
        pass
