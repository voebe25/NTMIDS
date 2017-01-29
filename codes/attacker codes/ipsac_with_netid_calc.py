from __future__ import print_function
import subprocess
import types
from scapy.all import *
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

def do_scan(target,options):
    parsed = None
    nmproc = NmapProcess(target, options)
    rc = nmproc.run()
    if rc != 0:
        print("nmap scan failed: {0}".format(nmproc.stderr))

    try:
        parsed = NmapParser.parse(nmproc.stdout)
    except NmapParserException as e:
        print("Exception raised while parsing scan: {0}".format(e.msg))

    return parsed

def print_scan(report):
   for host in report.hosts:
      for srv in host.services:
         print("{0} port {1} protocol {2} service is {3}".format(str(srv.port),srv.protocol,srv.service,srv.state))

def arp_scan(ipandsub):
   packet = Ether(dst = "ff:ff:ff:ff:ff:ff" )/ARP(pdst=ipandsub)
   ans,unans = srp(packet,timeout=2,iface="eth0")
   for s,r in ans:
      report = do_scan(r.sprintf("%ARP.psrc%" ),"-sV")
      if report:
         print_scan(report)
      print(r.sprintf("%Ether.src% ,%ARP.psrc%" ))
	  
def calculate_network_id(ip_bin,subnet):
   subnet_position = (subnet/8) 
   position_boundary = (subnet % 8) 
   calc_octet = ['0','b']
   if position_boundary > 0:
      for i in range(2,position_boundary+2):
         calc_octet.append(ip_bin[subnet_position][i])
      for i in range(position_boundary+2,10):
         calc_octet.append('0')
      ip_bin[subnet_position] = ''.join(calc_octet)
      if subnet_position < 3:
         for i in range(subnet_position+1,len(ip_bin)):
            ip_bin[i] = '0b00000000'
         
   if (position_boundary == 0 ):
      for i in range(subnet_position,len(ip_bin)):
         ip_bin[i] = '0b00000000'
   for i in range(0,4):
      net_addr.append(ip_bin[i])
   return net_addr
   
ip = '192.168.59.133' 
ip_list = ip.split(".")
ip_bin = []
for i in ip_list:
   each_bin = str(bin(int(i))).lstrip("0b")
   if len(each_bin) < 10:
      if len(each_bin) < 8:
         for j in range(1,(9 - len(each_bin))):
            each_bin = '0'+str(each_bin)
      each_bin = '0b'+str(each_bin)
   ip_bin.append(each_bin)     	  

proc = subprocess.Popen('ifconfig',stdout=subprocess.PIPE)
while True:
    line = proc.stdout.readline()
    if 'HWaddr' in line:
        break
mask = proc.stdout.readline().rstrip().split(b':')[-1]
mask = mask.split(".")
mask_bin = []
subnet = 0
net_addr = []
for i in mask:
   bin_eq  = bin(int(i))
   mask_bin.append(bin_eq)
   for i in range(2,len(str(bin_eq))):
      if bin_eq[i] == "1":
         subnet += 1
netid = calculate_network_id(ip_bin,subnet)
network_id = str(int(netid[0],2))+"."+str(int(netid[1],2))+"."+str(int(netid[2],2))+"."+str(int(netid[3],2))
print(network_id)
ipandsub = network_id+"/"+str(subnet)
arp_scan(ipandsub)
