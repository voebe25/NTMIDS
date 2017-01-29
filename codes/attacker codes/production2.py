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
from testspeed import internet_speed
from random import randint 
import math

class MyProcess(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
    def traffic_data(self,packet):
        global traffic_text
        global report_http,report_https,report_icmp,report_arp,report_dnsqry,report_udp,report_dhcp,report_ftp,report_telnet,report_ssh
        data=""
        if packet:
            raw = packet.sprintf('%Raw.load%')
            if packet.haslayer(TCP):
                data = str(packet.getlayer(IP).src) +" has trafic to "+str(packet.getlayer(IP).dst)+" on "+str(packet.getlayer(TCP).dport)+" port\n" 
                #global traffic_text
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
            if "https" in data:
                report_https +=  1
            elif "http" in data:
                report_http += 1
            elif "ICMP" in data:
                report_icmp += 1
            elif "ARP" in data:
                report_arp += 1
            elif "DNS Qry" in data:
                report_dnsqry += 1
            if "ftp" in data:
                report_ftp += 1
            if "UDP" in data:
                report_udp += 1
            if "DHCP" in data:
                report_dhcp += 1
            if "telnet" in data:
                report_telnet += 1
            if "ssh" in data:
                report_ssh += 1
       
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
        global ip_scan_text
        print self.values
        count = 1
        while count<5:
            ip_scan_text.delete(8.11)
            ip_scan_text.insert(8.11,"\\")
            time.sleep(0.2)
            ip_scan_text.delete(8.11)
            ip_scan_text.insert(8.11,"|")
            time.sleep(0.2)
            ip_scan_text.delete(8.11)
            ip_scan_text.insert(8.11,"/")
            time.sleep(0.2)
            ip_scan_text.delete(8.11)
            ip_scan_text.insert(8.11,"-")
            time.sleep(0.2)
            ip_scan_text.delete(8.11)
            ip_scan_text.insert(8.11,"\\")
            time.sleep(0.2)
            ip_scan_text.delete(8.11)
            ip_scan_text.insert(8.11,"-")
            ip_scan_text.see(END)
            ip_scan_text.update_idletasks()
            time.sleep(0.2)
            count += 1
        ip_scan_text.delete(1.0,END)
        for i in self.values:
            ip_scan_text.image_create(END,image=self.photoImg)
            ip_scan_text.insert(END,str(" <------> "+i+"\n"))
            ip_scan_text.see(END)
            ip_scan_text.update_idletasks()
        ip_scan_text.config(state=DISABLED)
        #Below is the code for new system detection..(Dont delete!)
        '''global ip_mac_bindings
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
              ip_scan_text.tag_add("( NEW SYSTEM )",idx2,pos2) '''
        notebook.tab(1,state="normal")

class Application(ttk.Frame):
    def __init__(self, master=None):
        ttk.Frame.__init__(self, master)
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
        ip_scan_text = Text(Frame1,background="black",borderwidth=5,foreground="green",font=('Helvetica',10,'bold'),yscrollcommand=scrollbar1.set)
        ip_scan_text.pack(fill=BOTH)
        for i in range(1,8):
           ip_scan_text.insert(END,"\n")
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
        traffic_text = Text(Frame2,background="black",borderwidth=5,foreground="yellow",yscrollcommand=scrollbar2.set)
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
        try:
           sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           sock.connect(("192.168.59.136",10000)) # Get this ip address from scanning and confirming with db
           print "connection made"
           sock.sendall("Getinfo")
           r = sock.recv(4096)
           print "received info !"
           sock.close() 
        except:
           r = "Host doesnt respond , it may be down !"
        #print r        
        window = Toplevel()
        temp_Frame = Frame(window)
        temp_Frame.pack()
        temp_user_scroolbar = Scrollbar(temp_Frame)
        temp_user_scroolbar.pack(side=RIGHT,fill=Y)
        temp_user_info = Text(temp_Frame,background="blue",foreground="white",yscrollcommand=temp_user_scroolbar.set)
        temp_user_info.pack(fill=BOTH)
        temp_user_info.insert(END,r)
        temp_user_scroolbar.config(command=temp_user_info.yview)
        temp_user_info.config(state=DISABLED)       

    def __init__(self,master=None):
        ttk.Frame.__init__(self,master)
        self.master.grid()
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

class Updown_speed(threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
      self.updown=[]
      self.output=""
   def run(self):
      self.updown = internet_speed()
      for i in self.updown:
         self.output += str(i+"\n")
      canvas.itemconfig(speed_text,text=self.output)

class Application3(ttk.Frame):
    def __init__(self,master=None):
        ttk.Frame.__init__(self)
        self.update_idletasks()
        self.histogram_values = dict()  
        self.histogram_list = [2]
        self.traffic_names=["ARP","HTTP","ICMP","DNS-QRY","UDP","DHCP","FTP","TELNET","SSH"]
        for i in range(0,8):
           self.histogram_list.append(math.pow(self.histogram_list[i],2))  
        for i in range(0,8):
           self.histogram_values[self.histogram_list[i]] = 300 - ((i+1)*30)
        frame = Frame(master, width=400, height=30)
        frame.pack(fill='x')
        refresh = Button(frame, text='Refresh',command=self.draw_report)
        refresh.pack(side='right', padx=2)
        global canvas
        canvas = Canvas(master,width=900,height=600,background="grey")
        canvas.pack(fill=BOTH)
        
    def draw_report(self):
        canvas.delete("all")
        global report_http,report_https,report_icmp,report_arp,report_dnsqry,report_udp,report_dhcp,report_ftp,report_telnet,report_ssh
        self.speed_worker = Updown_speed()
        self.speed_worker.start()
        global speed_text
        speed_text = canvas.create_text(10,10,anchor="nw")
        start_point = 40
        width = 80
        height = 300
        list=[]
        temp_arp=0
        temp_http=0
        temp_icmp=0
        temp_dnsqry=0
        temp_udp = 0
        temp_dhcp = 0
        temp_ftp = 0
        temp_telnet = 0
        temp_ssh = 0
        for i in self.histogram_list:
           if i<report_arp:
                temp_arp = i
           if i<report_http:
                temp_http = i
           if i<report_icmp:
                temp_icmp = i
           if i<report_dnsqry:
                temp_dnsqry = i
           if i<report_udp:
                temp_udp = i
           if i<report_dhcp:
                temp_dhcp = i
           if i<report_ftp:
                temp_ftp = i
           if i<report_telnet:
                temp_telnet = i
           if i<report_ssh:
                temp_ssh = i

        list.append(temp_arp)
        list.append(temp_http)
        list.append(temp_icmp)
        list.append(temp_dnsqry)
        list.append(temp_udp)
        list.append(temp_dhcp)
        list.append(temp_ftp)
        list.append(temp_telnet)
        list.append(temp_ssh)
        print list
        for i in range(1,10):
           end_point = start_point+width
           if list[i-1] == 0:
              y_point = 299
           else:
              y_point = self.histogram_values[list[i-1]]

           canvas.create_rectangle(start_point, y_point, end_point, height, fill="#2f4f4f")
           canvas.create_text(start_point+30,325,text=self.traffic_names[i-1])
           start_point += width+20
        report_icmp = 0
        report_http = 0
        report_https = 0
        report_arp = 0
        report_dnsqry = 0
        report_udp = 0
        report_dhcp = 0
        report_ftp = 0
        report_telnet = 0
        report_ssh = 0

#Testing new threaded model for message sending

class send_unicast(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        
    def run(self):
        conf_text=""
        try:
           sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
           sock.settimeout(2)
           sock.connect((sendto,10000))
           sock.send(data1)
           sock.close()
           conf_text="Message sent !"
        except:
           conf_text = "Unable to send data , host is not running agent."
        confirmation_2.config(state="normal")
        confirmation_2.delete("1.0",END)
        for i in range(1,5):
           confirmation_2.insert(END,"\n")
        confirmation_2.insert(END,conf_text,"center-tag")
        confirmation_2.config(state="disabled")

class send_broadcast(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        for i in broadcast_to:
            try:
               sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
               sock.settimeout(2)
               sock.connect((i,10000))
               sock.send(data)
               sock.close()
            except:
               pass
        confirmation.config(state="normal")
        confirmation.delete("1.0",END)
        for i in range(1,5):
            confirmation.insert(END,"\n")
        confirmation.insert(END,"Message sent !","center-tag")
        confirmation.config(state="disabled")

#Testing code complete

def send_message_broadcast():  #Sends the message to a every user
    global broadcast_to
    broadcast_to = ["192.168.59.136","192.168.59.136","192.168.59.136","192.168.59.136","192.168.59.136","192.168.59.136","192.168.59.136","192.168.59.136","192.168.59.136","192.168.59.136"] #This will be updated from ip scan process and db!
    global broadcast_frame
    global message_text
    global send_window
    global confirmation
    global data
    data = "Message: "
    data += message_text.get("1.0",END)
    broadcast_frame.grid_forget()
    broadcast_frame = Frame(send_window)
    broadcast_frame.pack(fill=BOTH)
    confirmation = Text(broadcast_frame,foreground="green")
    confirmation.pack(fill=BOTH)
    confirmation.tag_configure("center-tag",justify="center")
    for i in range(1,5):
        confirmation.insert(END,"\n")
    confirmation.insert(END,"Trying to send ..","center-tag")
    print "Executing this ........."
    confirmation.config(state="disabled")
    broadcast_worker = send_broadcast()
    broadcast_worker.start()

def send_message_unicast(): #Sends the message to a single user
    global unicast_frame,to,message_text_uni,data1,confirmation_2,sendto
    sendto = to.get("1.0",END)
    data1 = "Message: "
    data1 += message_text_uni.get("1.0",END)
    unicast_frame.grid_forget()
    unicast_frame = Frame(send_unicast_window)
    unicast_frame.pack(fill=BOTH)
    confirmation_2 = Text(unicast_frame,foreground="green")
    confirmation_2.pack(fill=BOTH)
    confirmation_2.tag_configure("center-tag",justify="center")
    for i in range(1,5):
       confirmation_2.insert(END,"\n")
    confirmation_2.insert(END,"Trying to send ..","center-tag")
    confirmation_2.config(state="disabled")
    unicast_worker = send_unicast()
    unicast_worker.start()

def create_broadcast_msg(): # For sending broadcast message (creates message typing dialog and send button)
    global send_window
    send_window = Toplevel()
    send_window.update_idletasks()
    send_window.geometry("300x150+500+100")
    global broadcast_frame
    broadcast_frame = Frame(send_window,bg="black")
    broadcast_frame.grid()
    global message_text
    message_text = Text(broadcast_frame,background="blue",foreground="white",height=8,width=45)
    message_text.grid(row=0,column=0,sticky=W+E+N+S)
    send_button = Button(broadcast_frame,text="Send",command=send_message_broadcast)
    send_button.grid(row=1,column=0,sticky=W+E+N+S)

def create_specific_msg(): # For sending to specific user (creates message typing dialog and send button)
    global send_unicast_window
    send_unicast_window = Toplevel()
    send_unicast_window.update_idletasks()
    send_unicast_window.geometry("300x170+500+100")
    global unicast_frame
    unicast_frame = Frame(send_unicast_window)
    unicast_frame.grid()
    global message_text_uni,to
    label = Label(unicast_frame,text="To: ")
    label.grid(row=0,column=0)
    to = Text(unicast_frame,background="grey",foreground="black",height=1,width=45)
    to.grid(row=1,column=0)
    label2 = Label(unicast_frame,text="Message: ")
    label2.grid(row=2,column=0)
    message_text_uni = Text(unicast_frame,background="blue",foreground="white",height=5,width=45)
    message_text_uni.grid(row=3,column=0,sticky=W+E+N+S)
    send_button = Button(unicast_frame,text="Send",command=send_message_unicast)
    send_button.grid(row=4,column=0,sticky=W+E+N+S)
		
def main():
   global report_http,report_https,report_icmp,report_arp,report_dnsqry,report_udp,report_dhcp,report_ftp,report_telnet,report_ssh,traffic_text,ip_scan_text
   report_http = 0
   report_https = 0
   report_icmp = 0
   report_arp = 0
   report_dnsqry = 0
   report_udp = 0
   report_dhcp = 0
   report_ftp = 0
   report_telnet = 0
   report_ssh = 0
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
   style = ttk.Style()
   style.configure("My.TFrame",background="black")
   global notebook
   notebook = ttk.Notebook(root)
   notebook.pack()
   menubar = Menu(root,relief="raised",borderwidth=5)
   root.config(menu = menubar )
   filemenu = Menu(menubar)
   filemenu2 = Menu(menubar)
   menubar.add_cascade(label="Actions", menu=filemenu)
   menubar.add_cascade(label="Send Message", menu=filemenu2)
   filemenu.add_command(label="Update Users")
   filemenu.add_command(label="Dummy")
   filemenu2.add_command(label="Broadcast",command=create_broadcast_msg)
   filemenu2.add_command(label="Specific User",command=create_specific_msg)
   #filemenu2.add_command(label="Broadcast",command=create_b_instance)
   #filemenu2.add_command(label="Specific User",command=create_u_instance)
   mainframe = ttk.Frame(notebook)
   mainframe2 = ttk.Frame(notebook,style="My.TFrame")
   mainframe3 = ttk.Frame(notebook)
   app = Application(master=mainframe)
   app2 = Application2(master=mainframe2)
   app3 = Application3(master=mainframe3)
   notebook.add(mainframe,text="Monitor")
   notebook.add(mainframe2,text="Users",state="disabled")
   notebook.add(mainframe3,text="Report")
   app3.draw_report()
   root.mainloop()

if __name__ == "__main__":
   main()
