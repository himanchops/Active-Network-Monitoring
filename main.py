import socket, cProfile
import sys
from decode import *
from gui import *
import os
import threading
thelist = []
j = 1
def show():
    global j
    def on_closing():
        global j
        j = 0
        tk.destroy()
    tk = Tk()
    Label(tk, text='MultiListbox').pack()
    mlb = MultiListbox(tk, (('No.', 5),('Destination', 40), ('Source', 20), ('Protocol', 10)))
    mlb.pack(expand=YES, fill=BOTH)
    tk.protocol("WM_DELETE_WINDOW",on_closing)
    i = 0
    while j:
        try:
            mlb.insert(END, (thelist[i][0], thelist[i][1], thelist[i][2], thelist[i][3]))
            tk.update()
            i += 1
        except:
            pass

def fillin():
    global j
    if os.geteuid() != 0:
        print("Root privileges needed")
        sys.exit()
    i = 1
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while j:
        raw_data, addr = conn.recvfrom(65535)
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
        thelist.append((i, ethernet.dest_mac_addr, ethernet.src_mac_addr,ethernet.proto))
        i += 1

def main():
    t1 = threading.Thread(target=fillin)
    t2 = threading.Thread(target=show)
    t1.start()
    t2.start()
    t2.join()
    t1.join()

if __name__ == '__main__':
    #cProfile.run('main()')
    main()
