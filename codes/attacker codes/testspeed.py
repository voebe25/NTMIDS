import subprocess
import re

def internet_speed():
   output = ""
   out = []
   try:
      command = subprocess.Popen("speedtest-cli",shell=True,stdout=subprocess.PIPE)
      output = command.communicate()[0]
   except:
      pass

   if "Could not retrieve" in output:
      output = ["Unable to connect"]
      return output
   elif "Download:" in output:
      out = output.split("\n")
      result=[]
      result.append(out[6])
      result.append(out[8])
      return result
   else:
      output = ["Unable to connect"]
      return output
   
#internet_speed()
