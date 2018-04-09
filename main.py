import socket, cProfile
import sys
from decode import *
from gui import *
import os
import threading
import time
from globalvars import thelist
from pcap import Pcap

finish = threading.Event()
saving = threading.Event()

def fillin():
    pcap = Pcap("capture.pcap")
    if os.geteuid() != 0:
        print("Root privileges needed")
        finish.set()
    i = 1
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while not finish.is_set():
        raw_data, addr = conn.recvfrom(65535)
        try:
            ethernet = Ethernet(raw_data)
            if ethernet.proto == 8:
                #IPV4
                ipv4 = IPv4(ethernet.data)
                if ipv4.proto == 1:
                    #Icmp
                    icmp = ICMP(ipv4.data)
                elif ipv4.proto == 6:
                    #Tcp
                    tcp = TCP(ipv4.data)
                elif ipv4.proto == 17:
                    #Udp
                    upd = UDP(ipv4.data)
                elif ipv4.proto == 88:
                    #Igmp
                    igmp = IGMP(ipv4.data)
            elif ethernet.proto == 1544:
                #Arp
                arp = ARP(ethernet.data)
            elif ethernet.proto == 13576:
                #Rarp
                rarp = RARP(ethernet.data)
            elif ethernet.proto == 56710:
                #Ipv6
                ipv6 = IPv6(ethernet.data)
        except:
            print(raw_data)
            print(ethernet.proto)
            print(ethernet.data)
            print(len(ethernet.data))
            print("not enough bytes")
            finish.set()
        thelist.append((i, ethernet.dest_mac_addr,
            ethernet.src_mac_addr,ethernet.proto, raw_data))
        if saving.is_set():
            pcap.write(raw_data)
        i += 1
    pcap.close()

def main():
    tk = Tk()
    tk.title("Active Network Monitoring")
    tk.geometry("200x120")
    tk.protocol("WM_DELETE_WINDOW",lambda:finish.is_set())

    options = Frame()
    options.pack(anchor=CENTER)
    choice = IntVar()
    button1 = Button(options,text="Send Packets", command=lambda: choice.set(1))
    button2 = Button(options,text="Read Packets", command=lambda: choice.set(2))
    button3 = Button(options,text="Quit", fg="red",command=lambda: choice.set(0))
    button1.pack()
    button2.pack()
    button3.pack()
    
    button1.wait_variable(choice)
    options.destroy()

    if(choice.get() == 1):
        options = Frame()
        options.pack()
        button1 = Button(options,text="TCP", command=lambda: choice.set(0))
        button2 = Button(options,text="UDP", command=lambda: choice.set(1))
        button3 = Button(options,text="ICMP",command=lambda: choice.set(2))
        button1.pack(side=TOP)
        button2.pack(side=TOP)
        button3.pack(side=BOTTOM)

        button1.wait_variable(choice)
        options.destroy()

    elif(choice.get() == 2):
        tk.geometry("500x500")
        bttns = Frame()
        bttns.pack()
        paused = IntVar()
        mlb = MultiListbox(tk, (('No.', 5),('Destination', 20), ('Source', 20), ('Protocol', 10)))
        mlb.pack(expand=YES, fill=BOTH)
        i = 0
        button1 = Button(bttns,text="Start", fg="green", command=lambda: paused.set(0))
        button1.pack(side=LEFT)
        button2_text = StringVar()
        button2_text.set("Pause")
        button2 = Button(bttns,textvariable=button2_text, fg="yellow", command =
                lambda: paused.set(1))
        button2.pack(side=LEFT)
        button3 = Button(bttns,text="save", fg="blue",command=lambda:
                saving.clear() if saving.is_set() else saving.set())
        button3.pack(side=LEFT)
        button4 = Button(bttns,text="Quit", fg="red",command=lambda: finish.set())
        button4.pack(side=LEFT)
        tk.update()
        t1 = threading.Thread(target=fillin)
        t1.start()
        while not finish.is_set():
            try:
                mlb.insert(END, (thelist[i][0], thelist[i][1], thelist[i][2], thelist[i][3]))
                tk.update()
                i += 1
                if paused.get():
                    button2.wait_variable(paused)
                    i = len(thelist)
            except:
                pass
        t1.join()
    tk.destroy()

if __name__ == '__main__':
    #cProfile.run('main()')
    main()
