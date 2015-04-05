---
layout: post
title: "NDH CTF 2015 - Cooper Writeup"
date: 2015-04-06 01:52:15 +0430
comments: true
categories: ctf ndh2k15 stegano 
---

**NDH 2015 Cooper Writeup**  
**Point = 300**  
**Category = Stegano**  

>"I am not crazy, my mother had me tested." (Sheldon)
>
>What did Sheldon ... huh sorry, Dr. Cooper really mean?
>(<http://quals.nuitduhack.com/challenges/view/14>)

The tar zip contains a Windows executable, so the first thing I did was opening it in CFF Explorer.
Doing so I found a picture of Sheldon ... or better say `"Dr. Cooper"` in resources and a section called .hidden containing a ZIP file.  

![Sheldon's picture](/files/ctf/ndh2k15/cooper/cooper.bmp "khkhkhhhhhh")  
<!--more-->
Within the zip file there was a C++ code project with encrypt and decrypt functions.

```
> dir Stegano-BMP-master
...
2013-06-21  05:24 PM               533 decrypt.cpp
2015-04-04  12:10 PM    <DIR>          easybmp
2013-06-21  05:24 PM               768 encrypt.cpp
2013-06-21  05:24 PM                28 main.cpp
2013-06-21  05:24 PM               564 Makefile
2013-06-21  05:24 PM               238 README.md
2013-06-21  05:24 PM             2,705 stegano.cpp
2013-06-21  05:24 PM               196 stegano.h
               7 File(s)          5,032 bytes
 ```
 
 First thing that strikes the mind is to compile the project and decrypt (extract) the flag from it, and I did, and I FAILED :(
 
 ```
 >decrypt cooper.bmp
 3
 
 ```
 Obviously `3` cannot be the flag! (but I did submit it and the server did reject it :))
 So I insepected the files more, and I found a [PDF](/pdfFile.pdf) file in the EXE's hex dump.
 I fixed and opened it and finally found "my precious"!
 
 ![tha flag](/files/ctf/ndh2k15/cooper/flag.jpg "StephenHawkingSpentSomeTimeOnSteganoTrolling")
 
BTW: The [PDF](/files/ctf/ndh2k15/cooper/pdfFile.pdf) is password protected which the reader has to guess :D
 
 Written by __[MMS](http://twitter.com/shabgrd)__
