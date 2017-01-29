from Tkinter import *
import threading
import time
import subprocess
import types
import socket
import string
from scapy.all import *
import re
from final_ip_scanner import start_scan
from PIL import Image,ImageTk

class MyProcess(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self._value = ""
    def traffic_data(self,packet):
        data=""
        if packet:
            raw = packet.sprintf('%Raw.load%')
            if packet.haslayer(TCP):
                data = str(packet.getlayer(IP).src) +" has trafic to "+str(packet.getlayer(IP).dst)+" on "+str(packet.getlayer(TCP).dport)+" port\n" 
                traffic_text.config(state=NORMAL)
                traffic_text.insert(END,data)
                traffic_text.see(END)
                traffic_text.update_idletasks()

            data = str(packet.summary())+"\n"
            traffic_text.config(state=NORMAL)
            traffic_text.insert(END,data)
            traffic_text.see(END)
            traffic_text.update_idletasks()
            traffic_text.config(state=DISABLED)
       
    def run(self):
        sniff(iface="eth0", prn = self.traffic_data)

class Myscanprocess(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.values = []
        self.image1 = Image.open("desktop_logo.png")
        self.photoImg = ImageTk.PhotoImage(self.image1)
    def run(self):
        self.values = start_scan()
        count = 1
        while count<10:
            ip_scan_text.delete(1.11)
            ip_scan_text.insert(1.11,"\\")
            time.sleep(0.2)
            ip_scan_text.delete(1.11)
            ip_scan_text.insert(1.11,"|")
            time.sleep(0.2)
            ip_scan_text.delete(1.11)
            ip_scan_text.insert(1.11,"/")
            time.sleep(0.2)
            ip_scan_text.delete(1.11)
            ip_scan_text.insert(1.11,"-")
            time.sleep(0.2)
            ip_scan_text.delete(1.11)
            ip_scan_text.insert(1.11,"\\")
            time.sleep(0.2)
            ip_scan_text.delete(1.11)
            ip_scan_text.insert(1.11,"-")
            ip_scan_text.see(END)
            ip_scan_text.update_idletasks()
            time.sleep(0.2)
            count += 1
        ip_scan_text.delete(1.0,END)
        #time.sleep(5)
        for i in self.values:
            ip_scan_text.image_create(END,image=self.photoImg)
            ip_scan_text.insert(END,str(" <------> "+i+"\n"))
            ip_scan_text.see(END)
            ip_scan_text.update_idletasks()
        ip_scan_text.config(state=DISABLED)

class Application(Frame):
    def __init__(self, master=None):
        Frame.__init__(self, master)
        self.grid()
        master.update_idletasks()
        self.worker = MyProcess()
        self.ip_scan_worker = Myscanprocess()
        self.worker.start()
        self.ip_scan_worker.start()
        self.quote = """Module under construction .."""
        for r in range(6):
            self.master.rowconfigure(r, weight=1)    
        for c in range(5):
            self.master.columnconfigure(c, weight=1)
        Frame1 = Frame(master, bg="red")
        Frame1.grid(row = 0, column = 0, rowspan = 4, columnspan = 1, sticky = W+E+N+S)
        scrollbar1 = Scrollbar(Frame1)
        scrollbar1.pack(side=RIGHT, fill=Y)
        label_ip_scan = Label(Frame1,text="Scanned IP-Mac Bindings",background="green")
        label_ip_scan.pack(fill=X)
        global ip_scan_text
        ip_scan_text = Text(Frame1,background="black",borderwidth=5,foreground="green",font=('Helvetica',10,'bold'))
        ip_scan_text.pack(fill=BOTH)
        ip_scan_text.tag_configure('tag-center', justify='center')
        ip_scan_text.insert(END,"Scanning.. ",'tag-center')
        scrollbar1.config(command=ip_scan_text.yview)	
        Frame2 = Frame(master, bg="blue")
        Frame2.grid(row = 4, column = 0, rowspan = 2, columnspan = 5, sticky = W+E+N+S)
        #global scrollbar2
        scrollbar2 = Scrollbar(Frame2)
        scrollbar2.pack(side=RIGHT, fill=Y)
        label_traffic = Label(Frame2,text="Network Traffic View",background="yellow")
        label_traffic.pack(fill=X)
        global traffic_text
        traffic_text = Text(Frame2,background="black",borderwidth=5,foreground="yellow")
        traffic_text.pack(fill=BOTH)
        scrollbar2.config(command=traffic_text.yview)
        Frame3 = Frame(master, bg="green")
        Frame3.grid(row = 0, column = 1, rowspan = 4, columnspan = 5, sticky = W+E+N+S)
        scrollbar3 = Scrollbar(Frame3)
        scrollbar3.pack(side=RIGHT, fill=Y)
        label_alert = Label(Frame3,text="Alert ! Suspicious Traffic",background="red")
        label_alert.pack(fill=X)
        alert_text = Text(Frame3,background="black",borderwidth=5,foreground="red",font=('Helvetica',12,'bold'))
        alert_text.pack(fill=BOTH)
        scrollbar3.config(command=alert_text.yview)
        alert_text.insert(END,self.quote)
        alert_text.config(state=DISABLED)
		
def main():
   root = Tk()
   root.geometry("1000x600+100+100")
   root.title("Zucknet")
   app = Application(master=root)
   app.mainloop()
   
if __name__ == "__main__":
   main()
