from scapy.all import *

def ICMPpacket(source, destination, time, t, raw_load):
	packet = IP(src=source, dst=destination, ttl = time, type = t)/ICMP()/raw_load
	send(packet)
	packet.show()

def TCPpacket(destination, sp, dp) :
	packet = IP(dst=destination)/TCP(sport=sp, dport=dp)
	send(packet)
	packet.show()
	return packet

def UDPpacket(destination, sp, dp):
	packet = IP(dst=destination)/UDP(sport=sp, dport=dp)
	send(packet)
	packet.show()

def TraceRoute(destination, m):
	traceroute([destination], maxttl = m)

#output=sr(IP(dst='google.com')/ICMP())
#print '\nOutput is:'
#print output
#result, unanswered=output
#print '\nResult is:'
#print result
