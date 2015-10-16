#!/usr/bin/python
# -*- coding: utf-8 -*-

# Sniff every types of files you want on your network interface and save it.
#
# 2015/10/10
# by Oros
#
# Setup :
# $ sudo apt-get install python-scapy
# http://secdev.org/projects/scapy/doc/usage.html
#
# Help :
# $ files_sniffer.py -h
#
# Default usage :
# Sniff every jpeg, png and git files and save it in /tmp/sniffer/
# $ sudo files_sniffer.py
#
# Example :
# $ sudo python files_sniffer.py -i eth0 -o /dev/shm/sniffer -c "text/html; charset=iso-8859-1,image/vnd.microsoft.icon,image/jpeg,image/png,image/gif" --min-size 100 --max-size 1000000 
# Sniff on eth0 and save file in /dev/shm/sniffer, if :
#	 content-type is in :
#		text/html; charset=iso-8859-1
#		image/vnd.microsoft.icon
#		image/jpeg
#		image/png
#		image/gif
#	and Content-Length > 100 octets
#	and Content-Length < 1 000 000 octets
#
# List of content-type : https://www.iana.org/assignments/media-types/media-types.xhtml

import io
import time
import os
import optparse
try:
	from scapy.all import sniff
	from scapy.all import TCP
	from scapy.all import Raw
	from scapy.all import IP
except ImportError:
	import sys
	sys.exit("\033[31mYou need to setup python-scapy\033[0m\nsudo apt-get install python-scapy")


output_directory="/tmp/sniffer/"
min_size=0
max_size=5000000
content_type=["image/jpeg","image/png","image/gif"]
prefix_filter=""
suffix_filter=""
time_out=30
purge_time=10

def purge():
	global last_purge
	global headers
	global packets
	last_purge=time.time()
	to_del=[]
	for x in packets:
		if packets[x]['up_time']+time_out < time.time():
			to_del.append(x)
	for x in to_del:
		del packets[x]
	to_del=[]
	for x in headers:
		if headers[x]['up_time']+time_out < time.time():
			to_del.append(x)
	for x in to_del:
		del headers[x]
	del to_del

def find_files(x):
	global headers
	global packets
	if TCP in x:
		src= x.sprintf("%IP.src%")
		dst= x.sprintf("%IP.dst%")
		sport= x.sprintf("%TCP.sport%")
		dport= x.sprintf("%TCP.dport%")
		seq= x.sprintf("%TCP.seq%")
		chksum= x.sprintf("%TCP.chksum%")
		ack= x.sprintf("%TCP.ack%")
		flags= x.sprintf("%TCP.flags%")
		packet_id=src+"#"+dst+"#"+sport+"#"+ack
		if "Raw" in x[TCP]:
			if packet_id not in packets:
				r=x.sprintf("%Raw.load%").split('\\r\\n')
				if len(r) >1:
					if r[1][:6] == "Host: ":
						# query
						file_name=r[1][6:]
						if r[0][:4] == "'GET":
							file_name+=r[0][5:].split(' HTTP')[0]
							# Not perfect
							file_name=file_name.replace('/', '_').replace('.', '_').replace(':', '_').replace('?', '_').replace('<', '_').replace('>', '_').replace('&', '_')

							headers[packet_id]={"seq":[seq],'name':file_name, 'up_time':time.time()}

				if dst+"#"+src+"#"+dport+"#"+seq in headers:
					raw=bytes(x.getlayer(Raw))
					head=raw[:raw.find('\r\n\r\n')].split("\r\n")
					data=raw[raw.find('\r\n\r\n')+4:]
					content_length=0
					is_ok=False
					for d in head:
						if d[:14] == "Content-Type: ":
							if not d[14:] in content_type:
								is_ok=False
								if packet_id in headers:
									del headers[packet_id]
								if dst+"#"+src+"#"+dport+"#"+seq in headers:
									del headers[dst+"#"+src+"#"+dport+"#"+seq]
								break
							else:
								is_ok=True
						elif len(d)>16 and d[:16] == "Content-Length: ":
							content_length=int(d[16:])
							if content_length > max_size or content_length < min_size:
								is_ok=False
								if packet_id in headers:
									del headers[packet_id]
								if dst+"#"+src+"#"+dport+"#"+seq in headers:
									del headers[dst+"#"+src+"#"+dport+"#"+seq]
								break
					if is_ok:
						packets[packet_id]={ 'seq':[seq],
											'head':head,
											'headers_key':dst+"#"+src+"#"+dport+"#"+seq,
											'data':data,
											'content_length':content_length,
											'up_time':time.time()
											}

			if packet_id in packets:
				if seq not in packets[packet_id]['seq']:
					packets[packet_id]['seq'].append(seq)
					if 'data' not in packets[packet_id]:
						packets[packet_id]['data']=bytes(x.getlayer(Raw))
					else:
						packets[packet_id]['data']+=bytes(x.getlayer(Raw))
					packets[packet_id]['up_time']=time.time()
					headers[packets[packet_id]['headers_key']]['up_time']=time.time()

					if len(packets[packet_id]['data']) == packets[packet_id]['content_length']:
						if packet_id in packets:
							headers_key=packets[packet_id]['headers_key']
							if headers_key in headers:
								if headers[headers_key]['name'] != '':
									print(output_directory+headers[headers_key]['name'])
									with io.open(output_directory+headers[headers_key]['name'], 'wb') as f:
										f.write(packets[packet_id]['data'])
								del packets[packet_id]
								del headers[headers_key]
								if headers_key in packets:
									del packets[headers_key]
								if packet_id in headers:
									del headers[packet_id]
							else:
								del packets[packet_id]

		if last_purge + purge_time < time.time():
			purge()


parser = optparse.OptionParser(usage="%prog: [options]")
parser.add_option("-i", "--iface", dest="iface", default='', help="Interface")
parser.add_option("-o", "--output", dest="directory", default=output_directory, help="Output directory. Default : "+output_directory)
parser.add_option("-c", "--ctype", dest="content_type", default=','.join(content_type), help="""Content-type separate by ','.
					List of content-type : https://www.iana.org/assignments/media-types/media-types.xhtml
					Default : """+','.join(content_type))
parser.add_option("", "--min-size", dest="min_size", default=str(min_size), help="Min file size in octets. Default : "+str(min_size))
parser.add_option("", "--max-size", dest="max_size", default=str(max_size), help="Max file size in octets. Default : "+str(max_size))
(options, args) = parser.parse_args()

if options.directory != "":
	output_directory=options.directory

if output_directory[-1:] != "/":
	output_directory+="/"

if not os.path.exists(output_directory):
	os.makedirs(output_directory)

if options.content_type != "":
	content_type=options.content_type.split(',')

if options.min_size != "":
	min_size=int(options.min_size)

if options.max_size != "":
	max_size=int(options.max_size)

packets={}
headers={}
last_purge=time.time()

if options.iface != "":
	sniff(store=0, prn=find_files, iface=options.iface)
else:
	sniff(store=0, prn=find_files)