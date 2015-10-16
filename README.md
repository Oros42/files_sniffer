# files_sniffer
Sniff every types of files you want on your network interface and save it.  
  
  
Setup
-----
```
$ sudo apt-get install python-scapy
```

  
Help
----
```
$ files_sniffer.py -h
```
  
  
Default usage
-------------
Sniff every jpeg, png and git files and save it in /tmp/sniffer/  
```
$ sudo files_sniffer.py
```
  
  
Example :  
```
$ sudo python files_sniffer.py -i eth0 -o /dev/shm/sniffer -c "text/html; charset=iso-8859-1,image/vnd.microsoft.icon,image/jpeg,image/png,image/gif" --min-size 100 --max-size 1000000 
```
Sniff on eth0 and save file in /dev/shm/sniffer, if :  
```
 content-type is in :  
	text/html; charset=iso-8859-1  
	image/vnd.microsoft.icon  
	image/jpeg  
	image/png  
	image/gif  
and Content-Length > 100 octets  
and Content-Length < 1 000 000 octets  
```
  
List of content-type : https://www.iana.org/assignments/media-types/media-types.xhtml  
