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
from testspeed import internet_speed
import math

class alert_suspicious_traffic(threading.Thread): # Thread for analyzing suspicious traffic and writing it in red area.(Brute force)
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
    def run(self):
        global brute
        now = int(round(time.time()*1000))
        for dst in dictionary_for_each_dst.keys():
            for src in dictionary_for_each_dst[dst].keys():
                for port in dictionary_for_each_dst[dst][src].keys():
                    temp_len = len(dictionary_for_each_dst[dst][src][port])
                    if temp_len < 3: # (3) just for testing puropse , in real env it should be greater than 50.
                        break
                    attack_temp_attempt = 0
                    for samay in reversed(xrange(temp_len-2)):
                        if (now - dictionary_for_each_dst[dst][src][port][samay]) > 350000:
                            break
                        if (dictionary_for_each_dst[dst][src][port][temp_len-1] - dictionary_for_each_dst[dst][src][port][samay])< 150000: # Just for testing purpose (150000)
                            attack_temp_attempt += 1
                        if attack_temp_attempt > 4: # Taking attempt thershold as (5), in real env it should be above 50.
                            try:
                                alert_text.insert(END,"A suspicious traffic from "+str(src)+" to "+str(dst)+" on port "+str(port)+"\n")
                                break
                            except:
                                pass
        brute = 0

def mac_flood_analysis():
    global macflood
    alert_text.insert(END,"Alert ! lot of unknown MAC addresses in network\n")
    macflood=0
    del unknown_macs[:]

class add_to_syn(threading.Thread):
    def __init__(self,sequence,src,dst):
        threading.Thread.__init__(self)
        self.seq = sequence
        self.src = src
        self.dst = dst
    def run(self):
        global syn_flood_attempt,alert_text
        if not self.src in syn_data["S"].keys():
            syn_data["S"][self.src]={}
        if not self.seq in syn_data["S"][self.src].keys():
            syn_data["S"][self.src][self.seq] = int(round(time.time()*1000)) 
            
        for i in syn_data["S"][self.src].keys():
                if (int(round(time.time()*1000)) - syn_data["S"][self.src][i]) > 20000: #(20 seconds)
                    syn_flood_attempt += 1 
                    del syn_data["S"][self.src][i]

        if syn_flood_attempt > 10: # Taking (10) JUST FOR DEMO PURPOSE.
            try:
                alert_text.insert(END,"SYN flooding from source = "+str(self.src)+" to destination = "+str(self.dst)+"\n")
                syn_flood_attempt -= 1
            except:
                pass
       
class check_ack(threading.Thread):
    def __init__(self,sequence,src,dst):
        threading.Thread.__init__(self)
        self.seq = sequence
        self.src = src
        self.dst = dst
    def run(self):
        global syn_flood_attempt,alert_text
        if syn_data:
            if self.src in syn_data["S"]:
                if (int(self.seq)-1) in syn_data["S"][self.src].keys():
                    try:
                        del syn_data["S"][self.src][int(self.seq)-1]
                    except:
                        pass
                for i in syn_data["S"][self.src].keys():
                    if (int(round(time.time()*1000)) - syn_data["S"][self.src][i]) > 20000:
                        syn_flood_attempt += 1 
                        try:
                            del syn_data["S"][self.src][i]
                        except:
                            pass
                    if syn_flood_attempt > 10:
                        try:
                            alert_text.insert(END,"SYN flooding from source = "+str(self.src)+" to destination = "+str(self.dst)+"\n")
                            syn_flood_attempt -= 1
                        except:
                            pass

class ping_attack_detect(threading.Thread):
    def __init__(self,src,dst,t):
        threading.Thread.__init__(self)
        self.src = src
        self.dst = dst
        self.t = t
    def run(self):
        global ping_attempt
        if not self.dst in ping_data.keys():
            ping_data[self.dst] = {}
            ping_data[self.dst][self.src]=[]
            ping_data[self.dst][self.src].append(self.t)
        elif self.dst in ping_data.keys():
            if not self.src in ping_data[self.dst].keys():
                ping_data[self.dst][self.src]=[]
                ping_data[self.dst][self.src].append(self.t)
            else:
                ping_data[self.dst][self.src].append(self.t)
        if len(ping_data)>0:
            for i in ping_data.keys():
                for j in ping_data[i].keys():
                    if len(ping_data[i][j]) < 5 : #Just for testing (5)
                        continue
                    else:
                        for k in reversed(xrange(len(ping_data[i][j])-2)):
                            if (self.t - ping_data[i][j][k]) > 600000:
                                ping_data[i][j] = []
                                break
                            else:
                                ping_attempt += 1
                                self.t = ping_data[i][j][k]
                                try:
                                    del ping_data[i][j][k]
                                except:
                                    pass
        if ping_attempt > 8:
            try:
                alert_text.insert(END,"A lots of PING from source = "+self.src+" to destination = "+self.dst+"\n")
                ping_attempt = 0
            except:
                pass           

class check_dhcp(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
    def run(self):
        global alert_text,dhcp_packets
        if dhcp_packets > 10:
            try:
                alert_text.insert(END,"A lot of false DHCP requests going on in the network \n")
                dhcp_packets = 0
            except:
                pass

class MyProcess(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
    def traffic_data(self,packet):
        global traffic_text,macflood,brute,dhcp_packets
        global report_http,report_https,report_icmp,report_arp,report_dnsqry,report_udp,report_dhcp,report_ftp,report_telnet,report_ssh
        data=""
        if packet:
            if values:
                for i in range(len(values)):
                    if (str(packet.src) in values[i]):
                        break
                    elif i==(len(values)-1):
                        if not packet.src in unknown_macs:
                            unknown_macs.append(packet.src)
                for i in range(len(values)):
                    if str(packet.dst) in values[i]:
                        break
                    elif i==(len(values)-1):
                        if not packet.dst in unknown_macs:
                            unknown_macs.append(packet.dst)     
       
            if packet.haslayer(IP):
                ip = packet.getlayer(IP)
            if packet.haslayer(ICMP):
                icmp = packet.getlayer(ICMP)
                if icmp.type == 8: 
                    try:
                        ping_worker =  ping_attack_detect(packet.getlayer(IP).src,packet.getlayer(IP).dst,int(round(time.time()*1000)))
                        ping_worker.start()
                    except:
                        pass
            if packet.haslayer(UDP):
                udp = packet.getlayer(UDP)
                if udp.sport == 68 and udp.dport == 67:
                    dhcp = packet.getlayer(DHCP)
                    if dhcp.options[0][1] == 1:
                        dhcp_packets += 1
                    if dhcp.options[0][1] == 3:
                        dhcp_packets -= 1
                    try:
                        if dhcp_packets > 10:
                            dhcp_worker = check_dhcp()
                            dhcp_worker.start()
                    except:
                        pass
                
            if packet.haslayer(DNS):
                dns = packet.getlayer(DNS)
                if dns.qr == 1:
                    if dns.id in dns_queries:
                        dns_queries[dns.id] += 1
                        if dns_queries[dns.id] > 1:
                            try:
                                alert_text.insert(END,"A dns spoof is taking place ! TWO ANSWERS FOUND\n")
                                del dns_queries[dns.id]
                            except:
                                pass
                    else:
                        try:
                            dns_queries[dns.id] = 1
                        except:
                            pass

            if len(dns_queries) > 5 : # This is (5) because of small environment so that dns queries id doesnt take much space.
                temp_counter = 0
                for i in dns_queries.keys():
                    if temp_counter > (len(dns_queries)-1):
                        break
                    del dns_queries[i]
                    temp_counter += 1
            if packet.haslayer(TCP):
                tcp = packet.getlayer(TCP)
                if tcp.sprintf('%TCP.flags%') == "S":
                    #start a thread to add it to syn_data
                    try:
                        add_to_syndata_worker = add_to_syn(int(tcp.seq),packet.getlayer(IP).src,packet.getlayer(IP).dst)
                        add_to_syndata_worker.start()
                    except:
                        pass
                if tcp.sprintf('%TCP.flags%') == "A":
                    #start a thread to check for ack in syn_data
                    try:
                        check_for_ack_worker = check_ack(int(tcp.seq),packet.getlayer(IP).src,packet.getlayer(IP).dst)
                        check_for_ack_worker.start()
                    except:
                        pass
                raw = packet.sprintf('%Raw.load%')
                attack_signs = ["login","Password","SSH","Please login with USER and PASS","USER","PASS","Welcome to"]
                data = str(packet.getlayer(IP).src) +" has trafic to "+str(packet.getlayer(IP).dst)+" on "+str(packet.getlayer(TCP).dport)+" port\n" 
                
                for i in attack_signs: # So that only login attempts gets in to dictionary 
                    if i in raw:
                        if packet.getlayer(TCP).sport > 1024: # Just because it may happen that keywords are contained in incoming traffic
                            packet.getlayer(TCP).sport = packet.getlayer(TCP).dport
                            temp = packet.getlayer(IP).src
                            packet.getlayer(IP).src = packet.getlayer(IP).dst
                            packet.getlayer(IP).dst = temp
                        if not packet.getlayer(IP).src in dictionary_for_each_dst: 
                            dictionary_for_each_dst[packet.getlayer(IP).src]={}
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst]={}
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst][packet.getlayer(TCP).sport]=[]
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst][packet.getlayer(TCP).sport].append(int(round(time.time()*1000)))

                        elif not packet.getlayer(IP).dst in dictionary_for_each_dst[packet.getlayer(IP).src]:
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst]={}
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst][packet.getlayer(TCP).sport]=[]
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst][packet.getlayer(TCP).sport].append(int(round(time.time()*1000)))
   
                        elif not packet.getlayer(TCP).sport in dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst]:
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst][packet.getlayer(TCP).sport]=[]
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst][packet.getlayer(TCP).sport].append(int(round(time.time()*1000)))

                        else:
                            dictionary_for_each_dst[packet.getlayer(IP).src][packet.getlayer(IP).dst][packet.getlayer(TCP).sport].append(int(round(time.time()*1000)))  
							
                        break
						
                if((len(dictionary_for_each_dst) >= 1) and (brute==0)): # Since only one destination could be in the dict but it can have many connections.
                    try:
                        alert_suspicious_worker = alert_suspicious_traffic()
                        brute = 1
                        alert_suspicious_worker.start()
                    except:
                        pass
                try:
                    traffic_text.config(state=NORMAL)
                    traffic_text.insert(END,data)
                    traffic_text.see(END)
                    traffic_text.update_idletasks()
                except:
                    pass
            
            if (len(unknown_macs) > 250) and macflood==0:
                alert_text.insert(END,"Alert ! lot of unknown MAC addresses in network\n")
                macflood=1
                mac_flood_analysis()

            data = str(packet.summary())+"\n"
            try:
                #traffic_text.config(state=NORMAL)
                traffic_text.insert(END,data)
                traffic_text.see(END)
                traffic_text.update_idletasks()
                #traffic_text.config(state=DISABLED)
            except:
                pass
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

class scanclass(threading.Thread): #Thread that will handle all arp scan till below class prints spinner.
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
    def run(self):
        global values
        values = start_scan()
        for i in values:
            start_index = i.index('>')
            chk_system = i[start_index+2:]
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((chk_system,10000))
                #you can try sending some data and modifying agent to respond a code so that you are confirmed !
                sock.close()
                agent_systems.append(chk_system)
            except:
                pass

class Myscanprocess(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        global values
        values = []
        self.daemon = True

    def run(self):
        global scan_worker,ip_scan_text
        try:
            scan_worker = scanclass()
            scan_worker.start()
        except:
            pass
        while (scan_worker.isAlive()):
            try:
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
            except:
                pass
        try:
            ip_scan_text.delete(1.0,END)
        except:
            pass
        counter = 0
        for i in values:
            counter += 1
            present = False
            for j in agent_systems:
                if j in i:
                    try:
                        ip_scan_text.image_create(END,image=photoImg)
                        ip_scan_text.insert(END,str("   "+i))
                        ip_scan_text.insert(END,"\n")
                        present = True
                        break
                    except:
                        pass
            if not present:
                    try:
                        ip_scan_text.tag_config(i,foreground="white")
                        ip_scan_text.tag_config("( No Agent )",foreground="white")
                        pos = str(counter)+".0"
                        ip_scan_text.image_create(END,image=photoImg)
                        ip_scan_text.insert(END,str("   "+i))
                        idx = ip_scan_text.search(i, pos, END)
                        pos = '{}+{}c'.format(idx, len(i))
                        ip_scan_text.tag_add(i, idx, pos)
                        ip_scan_text.insert(END," ( No Agent )\n")
                        idx2 = ip_scan_text.search("( No Agent )",pos,END)
                        pos2 = '{}+{}c'.format(idx2,len("( No Agent )"))
                        ip_scan_text.tag_add("( No Agent )",idx2,pos2)
                    except:
                        pass
        try:
            ip_scan_text.config(state=DISABLED)
            notebook.tab(1,state="normal")
        except:
            pass
class Application(ttk.Frame):
    def __init__(self, master=None):
        ttk.Frame.__init__(self, master)
        self.grid()
        master.update_idletasks()
        global agent_systems
        agent_systems = []
        self.worker = MyProcess()
        self.ip_scan_worker = Myscanprocess()
        for r in range(6):
            self.master.rowconfigure(r, weight=1)    
        for c in range(5):
            self.master.columnconfigure(c, weight=1)
        Frame1 = Frame(master, bg="red")
        Frame1.grid(row = 0, column = 0, rowspan = 4, columnspan = 1, sticky = W+E+N+S)
        scrollbar1 = Scrollbar(Frame1)
        scrollbar1.pack(side=RIGHT, fill=Y)
        label_ip_scan = Label(Frame1,text="Scanned IP-Mac Bindings",background="grey")
        label_ip_scan.pack(fill=X)
        global ip_scan_text
        ip_scan_text = Text(Frame1,background="#0000ff",borderwidth=5,foreground="white",font=('Helvetica',10,'bold'),yscrollcommand=scrollbar1.set)
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
        label_traffic = Label(Frame2,text="Network Traffic View",background="grey")
        label_traffic.pack(fill=X)
        global traffic_text
        traffic_text = Text(Frame2,background="#0000ff",borderwidth=5,foreground="white",yscrollcommand=scrollbar2.set)
        traffic_text.pack(fill=BOTH)
        scrollbar2.config(command=traffic_text.yview)
        Frame3 = Frame(master, bg="green")
        Frame3.grid(row = 0, column = 1, rowspan = 4, columnspan = 5, sticky = W+E+N+S)
        scrollbar3 = Scrollbar(Frame3)
        scrollbar3.pack(side=RIGHT, fill=Y)
        label_alert = Label(Frame3,text="Alert ! Suspicious Traffic",background="grey")
        label_alert.pack(fill=X)
        global alert_text
        alert_text = Text(Frame3,background="#0000ff",borderwidth=5,foreground="white",font=('Helvetica',10,'bold'),yscrollcommand=scrollbar3.set)
        alert_text.pack(fill=BOTH)
        scrollbar3.config(command=alert_text.yview)
        #alert_text.insert(END,self.quote)
        #alert_text.config(state=DISABLED)
        global photoImg
        image1 = Image.open("desktop_logo.png")
        photoImg = ImageTk.PhotoImage(image1)
        try:
            self.worker.start()
            self.ip_scan_worker.start()
        except:
            pass

class Application2(ttk.Frame):

    def user_details(self,num):
        try:
           sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
           ip = agent_systems[num]
           sock.connect((ip,10000)) # Getting this ip address from agent_systems
           sock.sendall("Getinfo")
           r = sock.recv(4096)
           sock.close() 
        except:
           r = "Host doesnt respond , it may be down !"
        window = Toplevel()
        temp_Frame = Frame(window)
        temp_Frame.pack()
        temp_user_scroolbar = Scrollbar(temp_Frame)
        temp_user_scroolbar.pack(side=RIGHT,fill=Y)
        temp_user_info = Text(temp_Frame,background="#0000ff",foreground="white",yscrollcommand=temp_user_scroolbar.set)
        temp_user_info.pack(fill=BOTH)
        temp_user_info.insert(END,r)
        temp_user_scroolbar.config(command=temp_user_info.yview)
        temp_user_info.config(state=DISABLED)       

    def __init__(self,master=None):  
        ttk.Frame.__init__(self,master)
        self.master.grid()
        self.buttons=[]

    def load_users_fn(self):
        load_users = Button(self.master,text="Load users",command=self.draw_users)
        load_users.grid(row=0,column=0,sticky=W+E+N+S)

    def draw_users(self):
        for r in range(0,200):
            self.master.rowconfigure(r, weight=1)    
        for c in range(0,10):
            self.master.columnconfigure(c, weight=1)
        row_count = 1
        col_count = 0
        for i in range(1,len(agent_systems)+1):
           if (i % 10) is 0:
              row_count += 1
              col_count = 0
           btn = Button(self.master,text="user"+str(i),command=(lambda i=i:self.user_details(i-1)))
           btn.grid(row=row_count,column=col_count,sticky=W+E+N+S)
           col_count += 1
           self.buttons.append(btn)
        #Extra Button just for dummy purpose.
        for i in range(col_count,50):
           if (i % 10) is 0:
              row_count += 1
              col_count = 0
           btn = Button(self.master,text="DUMMY"+str(i))
           btn.grid(row=row_count,column=col_count,sticky=W+E+N+S)
           col_count += 1  

    def self_destruction(self):
        for w in self.master.winfo_children():
            w.destroy()

class Updown_speed(threading.Thread):
   def __init__(self):
      threading.Thread.__init__(self)
      self.updown=[]
      self.output=""
   def run(self):
      try:
          self.updown = internet_speed()
          for i in self.updown:
             self.output += str(i+"\n")
          canvas.itemconfig(speed_text,text=self.output)
      except:
          pass

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
        canvas = Canvas(master,width=900,height=600,background="#778899")
        canvas.pack(fill=BOTH)
        
    def draw_report(self):
        canvas.delete("all")
        global report_http,report_https,report_icmp,report_arp,report_dnsqry,report_udp,report_dhcp,report_ftp,report_telnet,report_ssh
        try:
            self.speed_worker = Updown_speed()
            self.speed_worker.start()
        except:
            pass
        global speed_text
        speed_text = canvas.create_text(10,10,anchor="nw")
        start_point = 100
        width = 80
        height = 300
        for i in range(0,6):
            if int(self.histogram_list[i]) > 655555:
                temp = ">= 10000"
            elif int(self.histogram_list[i]) > 256:
                temp = ">= 1000"
            elif int(self.histogram_list[i]) == 256:
                temp = ">= 200"
            else:
                temp = ">= "+str(int(self.histogram_list[i]))
            canvas.create_text(40,290-(i*38),text=temp)
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
        for i in range(1,10):
           end_point = start_point+width
           if list[i-1] == 0:
              y_point = 299
           else:
              y_point = self.histogram_values[list[i-1]]

           canvas.create_rectangle(start_point, y_point, end_point, height, fill="#006400")
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
        for i in agent_systems:
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

def send_message_broadcast():  #Sends the message to a every user
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
    to = Text(unicast_frame,background="blue",foreground="white",height=1,width=45)
    to.grid(row=1,column=0)
    label2 = Label(unicast_frame,text="Message: ")
    label2.grid(row=2,column=0)
    message_text_uni = Text(unicast_frame,background="blue",foreground="white",height=5,width=45)
    message_text_uni.grid(row=3,column=0,sticky=W+E+N+S)
    send_button = Button(unicast_frame,text="Send",command=send_message_unicast)
    send_button.grid(row=4,column=0,sticky=W+E+N+S)

def refresh_ip():
    app2.self_destruction()
    app2.load_users_fn()
    notebook.tab(1,state=DISABLED)
    ip_scan_text.config(state=NORMAL)
    ip_scan_text.delete("1.0",END)
    for i in range(1,8):
           ip_scan_text.insert(END,"\n")
    ip_scan_text.tag_configure('tag-center', justify='center')
    ip_scan_text.insert(END,"Scanning.. ",'tag-center')
    global agent_systems
    agent_systems=[]
    refresh_ip_worker = Myscanprocess()
    refresh_ip_worker.start()
		
def main():
   global report_http,report_https,report_icmp,report_arp,report_dnsqry,report_udp,report_dhcp,report_ftp,report_telnet,report_ssh,traffic_text,ip_scan_text,agent_systems,syn_flood_attempt,dictionary_for_each_dst,unknown_macs,brute,macflood,dns_queries,syn_data,ping_data,ping_attempt,dhcp_packets
 
   syn_data={}
   dhcp_packets=0
   ping_attempt = 0
   syn_data["S"]={}
   ping_data={}
   dns_queries = {}
   brute=0
   macflood=0
   unknown_macs=[]
   syn_flood_attempt = 0
   dictionary_for_each_dst={}
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
   root = Tk()
   root.geometry("1000x600+100+100")
   root.title("Zucknet")
   style = ttk.Style()
   style.configure("My.TFrame",background="blue")
   global notebook
   notebook = ttk.Notebook(root)
   notebook.pack()
   menubar = Menu(root,relief="raised",borderwidth=5)
   root.config(menu = menubar )
   filemenu = Menu(menubar)
   filemenu2 = Menu(menubar)
   menubar.add_cascade(label="Actions", menu=filemenu)
   menubar.add_cascade(label="Send Message", menu=filemenu2)
   filemenu.add_command(label="Refresh ip scan",command=refresh_ip)
   filemenu.add_command(label="Dummy")
   filemenu2.add_command(label="Broadcast",command=create_broadcast_msg)
   filemenu2.add_command(label="Specific User",command=create_specific_msg)
   mainframe = ttk.Frame(notebook)
   mainframe2 = ttk.Frame(notebook,style="My.TFrame")
   mainframe3 = ttk.Frame(notebook)
   app = Application(master=mainframe)
   global app2
   app2 = Application2(master=mainframe2)
   app2.load_users_fn()
   app3 = Application3(master=mainframe3)
   notebook.add(mainframe,text="Monitor")
   notebook.add(mainframe2,text="Users",state="disabled")
   notebook.add(mainframe3,text="Report")
   app3.draw_report()
   root.mainloop()

if __name__ == "__main__":
   main()