from scapy.all import sniff, Ether, IP, ICMP
import matplotlib.pyplot as plt
import numpy as np

# Initialize global lists to store packet sizes and timestamps
packet_sizes = []
timestamps = []
def binary_to_text(binary):
    # Ensure the binary string length is a multiple of 8
    if len(binary) % 8 != 0:
        print("Warning: Binary string length is not a multiple of 8. Extra bits may be ignored.")

    # Convert binary string into ASCII text
    text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary) - len(binary) % 8, 8))
    return text
def handle_packet(packet):
    """ Handle each packet, extract size, and store it with a timestamp. """
    print(f"Packet IP Source Addr & Size: ", packet[IP].src)
    print(f"Packet Size: ", len(packet[ICMP].payload))

    if packet.haslayer(ICMP) and packet[IP].src == expected_src_ip:
        size = len(packet[ICMP].payload)
        packet_sizes.append(size)
        timestamps.append(packet.time)
        print(f"Handled Received ICMP packet size: {size} bytes")
        print(f"Handled Packet IP Source Addr: ", packet[IP].src)

def plot_and_decode_packet_sizes(packet_sizes, timestamps):
    """ Plot packet sizes and decode them into binary data based on size thresholds. """
    # Define thresholds (assuming 100 bytes for '0' and 500 bytes for '1')
    threshold = (1 + 2 ) / 2
    binary_data = ''.join(['0' if size < threshold else '1' for size in packet_sizes])

    # Plotting
    plt.figure(figsize=(10, 5))
    plt.plot(timestamps, packet_sizes, 'o-')
    plt.title('Amplitude Modulated Packet Sizes')
    plt.xlabel('Time')
    plt.ylabel('Packet Size (Bytes)')
    plt.grid(True)
    plt.show()

    print(f"Decoded binary data: {binary_data}")
    data_text = binary_to_text(binary_data)
    print(f"Tranlated to ASCII:", {data_text})

def main():
    # Start packet sniffing
    mac_adapter="c4:03:a8:d1:a6:82"
    ip_wifi="172.20.7.186"
    global expected_src_ip
    expected_src_ip = "10.0.0.4"  # Adjust as necessary

    # Start packet sniffing
    print("Starting ICMP packet capture...")
    
    #conf.iface="Loopback Pseudo-Interface 1"
    sniff(filter="icmp", prn=handle_packet, store=False, timeout=10)  # Adjust timeout as needed


    # After capture, process and plot
    if packet_sizes:
        plot_and_decode_packet_sizes(packet_sizes, timestamps)

if __name__ == "__main__":
    main()