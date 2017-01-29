from scapy.all import *

dst_ad = "192.168.40.131"
for k in range(1,254):
   src_ad = "192.168.40.%s"%(k)
   packet = Ether(src = RandMAC("*:*:*:*:*:*"),dst="00:50:56:C0:00:01") /IP(src=src_ad,dst=dst_ad)/ICMP()
   sendp(packet,iface="eth0")
