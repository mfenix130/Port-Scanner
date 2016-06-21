import argparse
import time
import sys
import threading
from scapy.all import *
from queue import Queue


q = Queue()

def parse_args():
	parser = argparse.ArgumentParser(description='Port scanner.')
	parser.add_argument('ip', help= 'The IP for port scan')
	parser.add_argument('ports', help= 'Port or port range to scan. Give port range in hyphenated form')
	args = parser.parse_args()


	if (args.ports.find('-') != -1):
		min_port, max_port = args.ports.split('-')
		if ((int(min_port) <= 0) or (int(max_port) > 65535)):
			print("Invalid Port/Range")
			sys.exit()
		else:
			return(args.ip, args.ports)
	elif ((int(args.ports) <= 0) or (int(args.ports) > 65535)):
		print("Invalid Port/Range")
		sys.exit()
	else:	
		return(args.ip, args.ports)

def check_ip(ip):
	ans = sr1(IP(dst=ip)/ICMP(), timeout = 2, verbose = 0)
	if not (ans is None):
		if (ans.getlayer(ICMP).type == 0):       # We got an Echo reply
			print("Host Up")
		else:
			print("Host Down")
			sys.exit()
	else:
		print("Host Down")
		sys.exit()

def scan_ports(ip, port):
	port = int(port)
	src_port = RandShort()				# Randomize source port numbers
	packet = IP(dst=ip)/TCP(sport=src_port, dport = port, flags = 'S')
	resp = sr1(packet, timeout = 1, verbose = 0)

	print_lock = threading.Lock()

	if (resp == None):
		with print_lock:
			print ("Port {} is filtered".format(port))
	elif resp.haslayer(TCP):
		if (resp.getlayer(TCP).flags == 0x12):		# We got a SYN-ACK
			send_rst = sr(IP(dst=ip)/TCP(sport=src_port,dport=port,flags='AR'), timeout = 1, verbose = 0)
			with print_lock:
				print ("Port {} is Open".format(port))
		elif (resp.getlayer(TCP).flags == 0x14):	# RST-ACK
			with print_lock:
				print ("Port {} is Closed".format(port))
		
		
def threader(ip):
	while True:
		port = q.get()
		scan_ports(ip, port)
		q.task_done()	


def main():
	ip, ports = parse_args()
	check_ip(ip)
	
	print("Starting Scan")
	start_time = time.time()
	
	if (ports.find('-') == -1):
		scan_ports(ip, ports)		# If there is only one port to scan; don't multithread
	elif (ports.find('-') != -1):
		for _ in range (10):
			t = threading.Thread(target = threader, args = (ip,))
			t.daemon = True
			t.start()

		min_port, max_port = ports.split('-')
		for i in range(int(min_port), int(max_port)+1):
			q.put(str(i))
	else:
		print("Abnormal Case")
		sys.exit()

	q.join()
	print("Scan Complete")
	print("Scan Duration: {}".format((time.time() - start_time)))


if __name__ == '__main__':
	main()
