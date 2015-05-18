---
layout: post
title: "DefConCTF 2015 Quals - Access Control Writeup"
date: 2015-05-19 00:52:48 +0430
comments: true
categories: RE defcon auth bypass
---

**DefConCTF 2015 Access-Control Writeup**  
**Point = 1**  
**Category = Reverse**  

TL;DR

we are given a binary which seems to be a client to access a server.

you can see my solution here:

```
import socket 
import telnetlib


s = socket.create_connection(("access_control_server_f380fcad6e9b2cdb3c73c651824222dc.quals.shallweplayaga.me", 17069))

cid =  s.recv(1024).split(" ")[2]
#cid = "H\"Y1)3IY+yEl\\3\n"
print cid , len(cid)
s80 = ord(cid[7])
print chr(s80)
s80 = s80 % 3
#s80 = 0
dst = cid[s80+1:s80+1+5]
print dst
p = "duchess" #grumpy
passw = ""

for i in range(5):
    passw += chr(ord(p[i]) ^ ord(dst[i]))
passw = list(passw)
print passw
for i in range(5):
    if ord(passw[i]) <= 0x1f:
        passw[i] = chr(ord(passw[i]) + ord(' '))
    if ord(passw[i]) == 0x7f:
        passw[i] = chr(ord(passw[i]) - 0x7E + 0x20)

passw = ''.join(passw)
print passw
print s.recv(1024)
#print s.recv(1024)
s.send("version 3.11.54\n")
print s.recv(1024)
s.send("duchess\n")
print s.recv(1024)
s.send(passw+"\n")
print s.recv(1024)

s.send("print key\n")
print s.recv(1024)
chall = s.recv(1024)
print chall
chall = chall.split(" ")[1]
print chall
#print s.recv(1024)

# compute answer on chall

dst = cid[s80+7:s80+7+5]
print dst
passw = ""

for i in range(5):
    passw += chr(ord(chall[i]) ^ ord(dst[i]))
passw = list(passw)
print passw
for i in range(5):
    if ord(passw[i]) <= 0x1f:
        passw[i] = chr(ord(passw[i]) + ord(' '))
    if ord(passw[i]) == 0x7f:
        passw[i] = chr(ord(passw[i]) - 0x7E + 0x20)

passw = ''.join(passw)
print passw, len(passw)

s.send(passw+"\n")




t = telnetlib.Telnet()
t.sock = s
t.interact()

```

Running the script:

```
$ python access-sol.py
XZI_}jT.'l@Km+
[..]

the key is: The only easy day was yesterday. 44564

hello duchess, what would you like to do?
```

@HAMIDx9
