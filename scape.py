from scapy.all import *

select = raw_input("1. ICMP	2.TCP	3.UDP	4.Traceroute ")
if select == '1':
	source = raw_input("SOURCE: ")
	destination = raw_input("DESTINATION: ")
	raw_load = raw_input("Load: ")
	time = int(raw_input("TTL: "))
	t = int(raw_input("Type: "))
	packet = IP(src=source, dst=destination, ttl = time, type = t)/ICMP()/raw_load
	send(packet)
	packet.show()

elif select == '2':
	destination = raw_input("DESTINATION: ")
	sp = int(raw_input("Source Port: "))	
	dp = int(raw_input("Destination Port: "))
	f = raw_input("S/A ").upper()
	packet = IP(dst=destination)/TCP(sport=sp, dport=dp, flags=f)
	send(packet)
	packet.show()

elif select == '3':
	destination = raw_input("DESTINATION: ")
	sp = int(raw_input("Source Port: "))	
	dp = int(raw_input("Destination Port: "))
	packet = IP(dst=destination)/UDP(sport=sp, dport=dp)
	send(packet)
	packet.show()

elif select == '4':
	destination = raw_input("DESTINATION: ")
	m = raw_input("Max TTL: ")
	traceroute([destination], maxttl = m)



#output=sr(IP(dst='google.com')/ICMP())
#print '\nOutput is:'
#print output
#result, unanswered=output
#print '\nResult is:'
#print result

