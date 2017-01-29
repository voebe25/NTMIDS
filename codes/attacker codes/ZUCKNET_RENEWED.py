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
import ttk
import sqlite3
from Agent import get_name

class MyProcess(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        #self._value = ""
        self.daemon = True
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
        self.daemon = True
        self.image1 = Image.open("desktop_logo.png")
        self.photoImg = ImageTk.PhotoImage(self.image1)
    def run(self):
        self.values = start_scan()
        print self.values
        count = 1
        while count<5:
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
        '''for i in self.values:
            ip_scan_text.image_create(END,image=self.photoImg)
            ip_scan_text.insert(END,str(" <------> "+i+"\n"))
            ip_scan_text.see(END)
            ip_scan_text.update_idletasks()
        ip_scan_text.config(state=DISABLED)'''
        global ip_mac_bindings
        ip_mac_bindings = {"dd:ff:cc:xx:ss:kk":"192.168.59.1","dd:gg:tt:pp:ss:kk":"192.168.59.3"}
        retrived_macs = ("dd:ff:cc:xx:ss:kk","dd:ff:tt:pp:ss:kk","dd:kk:tt:pp:ss:kk","dd:gg:tt:pp:ss:kk","dd:ff:gg:pp:ss:kk")
        counter =0;
        for i in retrived_macs:
           counter += 1
           present = False
           for j in rows:
              if i in j:
                 present = True
                 ip_scan_text.image_create(END,image=self.photoImg)
                 ip_scan_text.insert(END,str("---"+i))
                 ip_scan_text.insert(END,"\n")
           if not present:
              ip_scan_text.tag_config(i,foreground="red")
              ip_scan_text.tag_config("( NEW SYSTEM )",foreground="red")
              pos = str(counter)+".0"
              ip_scan_text.image_create(END,image=self.photoImg)
              ip_scan_text.insert(END,str("---"+i))
              idx = ip_scan_text.search(i, pos, END)
              pos = '{}+{}c'.format(idx, len(i))
              ip_scan_text.tag_add(i, idx, pos)
              ip_scan_text.insert(END," ( NEW SYSTEM )\n")
              idx2 = ip_scan_text.search("( NEW SYSTEM )",pos,END)
              pos2 = '{}+{}c'.format(idx2,len("( NEW SYSTEM )"))
              ip_scan_text.tag_add("( NEW SYSTEM )",idx2,pos2)  
        notebook.tab(1,state="normal")

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

class Application2(ttk.Frame):

    def user_details(self,num):
        self.details = get_name(num)
        self.mac = self.details[0]
        self.user_info ="User"+str(num+1)+"\n"
        self.user_info += "Connection will me made \n"
        self.user_info += " to -> "
        if self.mac in ip_mac_bindings:
            self.user_info += ip_mac_bindings[self.mac]
        self.user_info += "And data --> \n"
        for i in range(1,len(self.details)):
           self.user_info += str(self.details[i]+"\n")
        window = Toplevel()
        temp_Frame = ttk.Frame(window)
        temp_Frame.pack()
        temp_user_scroolbar = Scrollbar(temp_Frame)
        temp_user_scroolbar.pack(side=RIGHT,fill=Y)
        temp_user_info = Text(temp_Frame,background="blue",foreground="white",yscrollcommand=temp_user_scroolbar.set)
        temp_user_info.pack(fill=BOTH)
        temp_user_info.insert(END,self.user_info)
        temp_user_scroolbar.config(command=temp_user_info.yview)
        temp_user_info.config(state=DISABLED)
        self.details[:] = []        

    def __init__(self,master=None):
        ttk.Frame.__init__(self,master)
        self.master.grid()
        #self.master.config(bg="black")
        self.buttons=[]
        for r in range(200):
            self.master.rowconfigure(r, weight=1)    
        for c in range(10):
            self.master.columnconfigure(c, weight=1)
        row_count = 0
        col_count = 0
        for i in range(1,len(rows)+1):
           if (i % 10) is 0:
              row_count += 1
              col_count = 0
           btn = Button(self.master,text="user"+str(i),command=(lambda i=i:self.user_details(i-1)))
           btn.grid(row=row_count,column=col_count,sticky=W+E+N+S)
           col_count += 1
           self.buttons.append(btn)
        #Extra Button just for fun
        for i in range(col_count,50):
           if (i % 10) is 0:
              row_count += 1
              col_count = 0
           btn = Button(self.master,text="DUMMY"+str(i))
           btn.grid(row=row_count,column=col_count,sticky=W+E+N+S)
           col_count += 1  

class Application3(ttk.Frame):
    def __init__(self,master=None):
        ttk.Frame.__init__(self)
        temp_user_scroolbar = Scrollbar(self.master)
        temp_user_scroolbar.pack(side=RIGHT,fill=Y)
        temp_user_info = Text(self.master,background="blue",foreground="white",yscrollcommand=temp_user_scroolbar.set)
        temp_user_info.pack(fill=BOTH)
        self.details = get_name(0)
        temp_user_info.insert(END,self.details)
        temp_user_scroolbar.config(command=temp_user_info.yview)
        temp_user_info.config(state=DISABLED)
		
def main():
   con = sqlite3.connect('pc_details.db')
   global rows
   rows =()
   with con:
      cur = con.execute("SELECT MAC FROM PCS")
      rows = cur.fetchall()
   global ip_mac_bindings
   ip_mac_bindings={}
   root = Tk()
   root.geometry("1000x600+100+100")
   root.title("Zucknet")
   global notebook
   notebook = ttk.Notebook(root)
   notebook.pack()
   mainframe = ttk.Frame(notebook)
   mainframe2 = ttk.Frame(notebook)
   mainframe3 = ttk.Frame(notebook)
   app = Application(master=mainframe)
   app2 = Application2(master=mainframe2)
   app3 = Application3(master=mainframe3)
   notebook.add(mainframe,text="Monitor")
   notebook.add(mainframe2,text="Users",state="disabled")
   notebook.add(mainframe3,text="Report")
   root.mainloop()

if __name__ == "__main__":
   main()
