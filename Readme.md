# DNS Cache Poisoning

## Prerequisites ##

1. netfilerqueue
   To install netfilterqueue run this command in terminal:
	sudo apt-get install build-essential python-dev libnetfilter-queue-dev
   
   To check correctly installed:
	pip install NetfilterQueue

   if it shows errors: see your python path contains netfilterqueue or not. If not then append path using this command
	import os, sys
	sys.path.append(/usr/local/lib/python2.7/dist-packages)
	print(sys.path)
    

2. IPTables
3. scapy

### Step 1 : Add this rule to iptables ###

redirect all dns responses (udp and source port 53) to main.py:

sudo iptables -A INPUT -p udp  --sport 53 -j NFQUEUE --queue-num 1

-A => Append chain rule
-p => protocol
-sport => source port
-j => jump to target 
NFQUEUE => netfilterqueue
--queue-num 1 => queue number

### Step 2 : Run main.py ###

sudo python main.py -q 1 -s www.cricbuzz.com -d 1.2.3.4

### Step 3 : Check Spoofing/Poisioning ###

ping www.cricbuzz.com

## Delete rule to revert ## 

sudo iptables -D INPUT -p udp  --sport 53 -j NFQUEUE --queue-num 1
