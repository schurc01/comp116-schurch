ASSIGNMENT 1 - Packet Sleuth
=============================

By: Susannah Church
-------------------
COMP 116 Computer Systems Security
----------------------------------

set1.pcap
----------
1) How many packets are there in this set?
861 

2) What protocol is used to transfer files from PC to server?
FTP

3) Why is the protocol insecure? <br />
FTP sends files and credentials in plain text, with no encryption.

4) What is the secure alternative to the protocol used?
sftp

5) What is the IP address of the server?
192.168.1.8

6) What was the username and password used to give access to the server? <br />
username: defcon
  password: m1ngisablowhard

7) How many files were transferred?
6

8) What are the names of the files transferred? <br />
COaqQWnU8AAwX3K.jpg <br />
CDkv69qUsAAq8zN.jpg <br />
CNsAEaYUYAARuaj.jpg <br />
CLu-m0MwoAAgjkr.jpg <br />
CKBXgmOWcAAtc4u.jpg <br />
CJoWmoOUkAAAYpx.jpg <br />

set2.pcap
----------
10) How many packets are there in this set?
77982

11) How many plaintext username-password pairs are there in this packet
set?
12

12) Briefly describe how you found the password/username pairs. <br />
I used ettercap to find the username-passowrd pair, and dsniff
to find the anonymous accounts. <br />

Commands: <br />
dsniff -p set2.pcap <br />
ettercap -T -r set2.pcap | grep "PASS" <br />

13) For each user/password pair, identify protocol, server IP, port
and the corresponding domain name 

Protocol: UDP
Server IP: 192.168.1.200
Domain name: N/A
Port number: 161

Protocol: UDP
Server IP: 192.168.15.12
Domain name: N/A
Port number: 161

Protocol: UDP
Server IP: 10.5.10.10
Domain name: N/A
Port number: 161

Protocol: UDP
Server IP: 192.168.1.3
Domain name: N/A
Port number: 161

Protocol: UDP
Server IP: 10.150.23.31
Domain name: N/A
Port number: 161


Protocol: UDP
Server IP: 87.120.13.118
Domain name: 76.0d.78.57.d6.net
Port number: 143

14) How many are legitimate? <br />
Only 1 is a NON-generic account, and we know it is a legitimate
username-password pair because the server sends back an "OK LOGIN
OK" message after the user enters it according to the IMAP request.

set3.pcap
---------
15) How many username/password combinations are there? <br /> 
I found 11.

16) List Protocol, Server, Domain, Port.

Protocol: UDP
Server: 10.0.8.254
Domain: N/A
Port: 161


Protocol: TCP
Server: 162.222.171.208
Domain: forum.defcon.org
Port: 80


Protocol: UDP
Server: 10.5.10.10
Domain: N/A
Port: 161


Protocol: UDP
Server: 10.26.0.147
Domain: N/A
Port: 161

Protocol: UDP
Server: 192.168.1.11
Domain: N/A
Port: 161


Protocol: UDP
Server: 172.16.15.31
Domain: dhcp-172-16-15-31.dhcp-registration.tufts.edu
Port: 161

Protocol: UDP
Server: 10.0.8.253
Domain: N/A
Port: 161


Protocol: UDP
Server: 192.168.1.3
Domain: N/A
Port: 161


Protocol: UDP
Server: 192.168.1.200
Domain: N/A
Port: 161


Protocol: UDP
Server: 192.168.15.12
Domain: N/A
Port: 161


Protocol: TCP
Server: 54.191.109.23
Domain: ec2-54-191-109-23.us-west-2.compute.amazonaws.com
Port: 80

17) How many are legitimate? <br />
Only 1, the forum.defcon.org pair.
The amazonaws pair could not be verified.

18) List all IP addresses/ Hostnames from set3.pcap. <br /> 
See attached file. I used tcpdump to output information
about each packet to a file called question_18.txt.

General Questions
-----------------
19) How did you verify the successful user/pass combinations?
I searched on wireshark for a frame that contains the password
and then followed the TCP stream to reconstruct whether the
server that was checking the authentication approved the 
login or rejected it.

20) What are security suggestions you could give to the user?
Use secure protocols, like sftp and https instead of having passwords out in the open. Secure protocols will encrypt all traffic so that the passwords cannot be extracted in plaintext in this manner from pcap files.
