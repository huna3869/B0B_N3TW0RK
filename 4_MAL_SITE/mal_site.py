import nfqueue, socket
from scapy.all import *

# sudo iptables -A OUTPUT -p tcp --dport 80 -j NFQUEUE

def process(i,payload):
	isMal = 0
	f = open("mal_site.txt", 'r')
	mallist = []
	line = f.readline()
	while line:
		line = f.readline()
		mallist = mallist + [line.rstrip('\n')]
	f.close()
	data = payload.get_data()
	p = IP(data)
	if str(p).find("Host:") != -1:
		m = str(p).split("Host: ")
		n = m[1].split("\r")
		print n[0]

		for a in mallist:
			if a == "http://"+n[0]:
				isMal = 1
	if isMal:
		payload.set_verdict_modified(nfqueue.NF_DROP, str(p), len(p))
	else:
		payload.set_verdict_modified(nfqueue.NF_ACCEPT, str(p), len(p))

def main():
	q = nfqueue.queue()
	q.open()
	q.bind(socket.AF_INET)
	q.set_callback(process)
	q.create_queue(0)
	try:
		q.try_run()
	except KeyboardInterrupt, e:
		print "interruption"
	q.unbind(socket.AF_INET)
	q.close()

main()