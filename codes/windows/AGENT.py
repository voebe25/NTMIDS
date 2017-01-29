import win32api
import psutil
import socket

rows=[]
ip = socket.gethostbyname(socket.gethostname())
def get_info_func():
   users = psutil.users()
   users = users[0]
   rows.append("User Name : "+users[0])
   rows.append("\nSYSTEM PROCESSES :")
   procs = psutil.pids()
   for i in procs:
      try:
         p = psutil.Process(i)
         rows.append(p.name())
      except:
         pass
   rows.append("\nCPU Utilization = "+str(psutil.cpu_percent())+" % ")
   rows.append("\nDISK Partitions = "+str(psutil.disk_partitions()))
   rows.append("\nDISK USAGE : "+str(psutil.disk_usage('/')))
   p = psutil.net_io_counters(pernic=True)
   for i in p:
      rows.append("\n"+str(i+"====>"))
      count = 1
      for j in p[i]:
         if count == 1:
            rows.append(str("Bytes Sent : "+str(j)))  
         if count == 2:
            rows.append(str("Bytes Received : "+str(j))) 
         if count == 3:
            rows.append(str("Packets Sent : "+str(j))) 
         if count == 4:
            rows.append(str("Packets Received : "+str(j))) 
         if count == 5:
            rows.append(str("Input Errors : "+str(j))) 
         if count == 6:
            rows.append(str("Output Errors : "+str(j))) 
         if count == 7:
            rows.append(str("Dropped Input Packets : "+str(j))) 
         if count == 8:
            rows.append(str("Dropped Output Packets : "+str(j))) 
         count += 1

#get_info_func()
#print rows

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.bind((ip,10000))
sock.listen(1)
while True:
   sock_copy,addr= sock.accept()
   #print "got connection !"
   command = sock_copy.recv(1024)
   #print command
   if command.startswith("Message: "):
      win32api.MessageBox(0,command,"Admin")

   elif command.startswith("Getinfo"):
      rows = []
      get_info_func()
      #print rows
      output=""
      for i in range(len(rows)):
         output += rows[i]+"\n"
         #print output
      sock_copy.sendall(output)
      