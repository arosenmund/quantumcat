from scapy.all import sniff, IP, UDP
import matplotlib.pyplot as plt
import numpy as np


def binary_to_text(binary):
    # Ensure the binary string length is a multiple of 8
    if len(binary) % 8 != 0:
        print("Warning: Binary string length is not a multiple of 8. Extra bits may be ignored.")

    # Convert binary string into ASCII text
    text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary) - len(binary) % 8, 8))
    return text
# Global lists to store packet data
timestamps = []
ports = []

def handle_packet(packet):
    """ Handle each packet, logging the timestamp and destination port. """
    if packet.haslayer(UDP):
        current_time = packet.time  # Capture the timestamp of the packet
        dest_port = packet[UDP].dport  # Capture the destination port of the packet
        timestamps.append(current_time)
        ports.append(dest_port)
        print(f"Received UDP packet on port {dest_port} at time {current_time}")

def plot_and_decode_ports(ports):
    """ Plot the sequence of received ports and decode them into binary data. """
    # Assume the base port is the smallest port received
    base_port = min(ports)
    binary_data = ['0' if port == base_port else '1' for port in ports]

    # Converting list of binary strings into a single binary string
    binary_data = ''.join(binary_data)
    print(f"Decoded binary data: {binary_data}")
    data_text = binary_to_text(binary_data)
    print(f"Tranlated to ASCII:", {data_text})

    # Plotting
    plt.figure(figsize=(10, 5))
    plt.stem(timestamps, ports, linefmt='b-', markerfmt='bo', basefmt='r-')
    plt.title('Received Ports Over Time')
    plt.xlabel('Time (s)')
    plt.ylabel('Destination Port')
    plt.grid(True)
    plt.show()

def main():
    # Start packet sniffing
    print("Starting UDP packet capture...")
    sniff(filter="udp and portrange 12345-12350", prn=handle_packet, store=False, timeout=30)  # Adjust timeout as necessary

    # After capture, plot and decode
    if ports:
        plot_and_decode_ports(ports)

if __name__ == "__main__":
    main()