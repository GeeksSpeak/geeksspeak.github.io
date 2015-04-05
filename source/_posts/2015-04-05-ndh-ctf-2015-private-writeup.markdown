---
layout: post
title: "NDH CTF 2015 - Private Writeup"
date: 2015-04-05 15:43:15 +0430
comments: false
categories: ctf forensics scapy
---

**NDH 2015 Private Writeup**  
**Point = 100**  
**Category = Forensics**  
**Description : **  

> "The quiet you are, the more you are able to ear"

We've provided a pcapng file in this challenge. At first glance I thought it may be VoIP challenge because of description but after viewing packets , this assumption goes wrong. there were some STP , CDP and some ICMP packets . after some investigation in packets i found some unusual ICMP packets ! their identification fields were 0 ! all of them ! hmmm. seems somebody generated them manually by a packet generator . so i focused on them to find a pattern .actually their IP headers had a pattern and they were ASCII numbers ! sweet . that's easy . let's have some fun with Scapy . 

```
from scapy.all import *
from scapy.utils import rdpcap
flag=""
pkts=rdpcap("private.pcap")
for pkt in pkts:
	 if (ICMP in pkt and pkt[ICMP].type==8 and pkt[ICMP].id==0 ):
		flag += chr(pkt[IP].id)
print flag		

```

