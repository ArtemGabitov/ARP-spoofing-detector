import sys
from scapy.all import sniff, ARP

mac_table = {}

def process_arp(packet):\

    # ignore the packet if it doesnt have an arp layer
    if not packet.haslayer(ARP):
        return

    # extract the source IP and the destination IP
    src_ip = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc

    # Check if the IP is already in the mac table
    if src_ip in mac_table:

        #i f the mac address has changed, alert the user
        if mac_table[src_ip] != src_mac:

            print("\n" + "!"*40)
            print("WARNING! ARP-SPOOFING DETECTED")
            print(f"DEVICE WITH IP {src_ip} CHANGED ADDRESS")
            print(f"OLD MAC: {mac_table[src_ip]}")
            print(f"NEW MAC: {src_mac}")
            print("\n" + "!"*40)
    else:
        # register a new device if its not in the mac table
        mac_table[src_ip] = src_mac
        print(f"NEW HOST: {src_ip} - {src_mac}")

def main():
    print("Starting ARP-spoofing detection")
    try:
        # sniffing for arp packets
        sniff(filter="arp", prn=process_arp, store=0)
    except KeyboardInterrupt:
        print("Exiting ARP-spoofing detection")
        print("Current MAC table:")

        #prints the mac table when interrupted
        for ip, mac in mac_table.items():
            print(f"{ip} -> {mac}")
        sys.exit(0)

if __name__ == "__main__":
    main()


