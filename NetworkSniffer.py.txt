from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

# Function to process packets
def packet_callback(packet):

    print("\n============================")
    print("Packet Captured")

    # Check IP Layer
    if IP in packet:

        print("Source IP      :", packet[IP].src)
        print("Destination IP :", packet[IP].dst)

        # Protocol Type
        if TCP in packet:
            print("Protocol       : TCP")

        elif UDP in packet:
            print("Protocol       : UDP")

        else:
            print("Protocol       : Other")

        # Packet Size
        print("Packet Length  :", len(packet))

        # Packet Summary
        print("Summary        :", packet.summary())


print("Starting Network Sniffer...")
print("Capturing 10 packets...\n")

# Start sniffing
sniff(prn=packet_callback, count=10)

print("\nSniffing Finished.")