print("Script started")
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    print("=" * 60)

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print(f"Protocol Number: {packet[IP].proto}")

        if packet.payload:
            try:
                payload = bytes(packet.payload)
                print("Payload:")
                print(payload[:100])  # Display first 100 bytes
            except Exception:
                print("Payload: Unable to read")

    else:
        print("Non-IP Packet Captured")

print("=" * 60)
print("      BASIC NETWORK SNIFFER")
print("=" * 60)
print("Capturing packets... Press Ctrl + C to stop.\n")

try:
    sniff(prn=packet_callback, store=False)
except KeyboardInterrupt:
    print("\nPacket Sniffing Stopped.")