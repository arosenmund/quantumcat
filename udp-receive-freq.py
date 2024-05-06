from scapy.all import sniff, IP, UDP
import numpy as np
import matplotlib.pyplot as plt
import time
mac_adapter="c4:03:a8:d1:a6:82"
ip_wifi="172.20.7.186"

def binary_to_text(binary):
    # Ensure the binary string length is a multiple of 8
    if len(binary) % 8 != 0:
        print("Warning: Binary string length is not a multiple of 8. Extra bits may be ignored.")

    # Convert binary string into ASCII text
    text = ''.join(chr(int(binary[i:i+8], 2)) for i in range(0, len(binary) - len(binary) % 8, 8))
    return text

timestamps = []  # Global list to store packet timestamps

def handle_packet(packet):
    """ Callback function to handle each received packet and log the timestamp. """
    if packet.haslayer(UDP):
        current_time = time.time()
        timestamps.append(current_time)
        print(f"Packet received at {current_time}")

def plot_waveform(timestamps):
    """ Plot the waveform from packet intervals. """
    intervals = np.diff(timestamps)  # Calculate intervals between packet receptions
    times = np.cumsum(intervals)  # Calculate cumulative times for plotting
    frequencies = 1 / intervals  # Frequency calculation from intervals

    plt.figure(figsize=(10, 4))
    plt.step(times, frequencies, where='post', label='Frequency vs. Time')
    plt.title('Received Frequency Modulation')
    plt.xlabel('Time (s)')
    plt.ylabel('Frequency (Hz)')
    plt.grid(True)
    plt.legend()
    plt.show()
    
     # Decoding binary data
    binary_data = ''
    for freq in frequencies:
        if np.isclose(freq, 1.00, atol=0.05):  # Assuming frequency of '0' is around 1 Hz
            binary_data += '0'
        elif np.isclose(freq, 2.00, atol=0.05):  # Assuming frequency of '1' is around 2 Hz
            binary_data += '1'

    print("Decoded binary data:", binary_data)
    intervals = np.diff(timestamps)
    threshold = (max(intervals) + min(intervals)) / 2
    binary_data1 = ''.join(['0' if interval > threshold else '1' for interval in intervals])
    data_text = binary_to_text(binary_data)
    print(f"Decoded binary data: {binary_data1}")
    print(f"Tranlated to ASCII:", {data_text})

def main():
    # Network configuration
    global expected_src_ip
    expected_src_ip = ip_wifi  # Adjust as necessary
    listen_port = 666  # UDP port to listen on

    # Start packet sniffing
    print("Starting UDP packet capture...")
    sniff(filter=f"udp and port {listen_port}", prn=handle_packet, store=False, timeout=30)  # Adjust timeout as needed

    # After capture process and plot, ensure there are enough timestamps
    if len(timestamps) > 1:
        plot_waveform(timestamps)

if __name__ == "__main__":
    main()