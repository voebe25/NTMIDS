from scapy.all import *
import re
def print_data(packet):
   if packet:
      raw = packet.sprintf('%Raw.load%')
      if packet.haslayer(TCP):
         print str(packet.getlayer(IP).src) +" has trafic to "+str(packet.getlayer(IP).dst)+" on "+str(packet.getlayer(TCP).dport)+" port"
         '''if packet.haslayer(DNS Qry):
            print str(packet.getlayer(IP).src)+" searched for "+str(packet.getlayer(DNS Qry).qname)'''
      print packet.summary()
      if packet.haslayer(Raw):
         payload = packet.getlayer(Raw).load
         if 'GET' in payload:
            if 'google' in payload:
               r = re.findall(r'(?i)\&q=(.*?)\&', payload)
            if r:
               search = r[0].split('&')[0]
               r = re.findall(r'(?i)\&q=(.*?)\&', payload)
               print "searched for ",search   

sniff(iface="eth0", prn = print_data)
