from __future__ import print_function
import subprocess
import types
from scapy.all import *

def arp_scan(ipandsub):
   packet = Ether(dst = "ff:ff:ff:ff:ff:ff" )/ARP(pdst=ipandsub)
   ans,unans = srp(packet,iface="eth0",timeout=2)
   for s,r in ans:
      print(r.sprintf("%Ether.src% <--> %ARP.psrc%" ))
   
ip = '192.168.59.0' #Calculate it automatically if possible (network id for your host) , cidr is calculated below
proc = subprocess.Popen('ifconfig',stdout=subprocess.PIPE)
while True:
    line = proc.stdout.readline()
    if "HWaddr" in line:
        break
mask = proc.stdout.readline().rstrip().split(b':')[-1]
print(mask)
mask = mask.split(".")
subnet = 0
for i in mask:
   bin_eq  = bin(int(i))
   for i in range(2,len(bin_eq)):
      if bin_eq[i] == "1":
         subnet += 1
      print(bin_eq[i],end="")
   print() 
ipandsub = ip+"/"+str(subnet)
arp_scan(ipandsub)
