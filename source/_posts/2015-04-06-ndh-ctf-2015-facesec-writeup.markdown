---
layout: post
title: "NDH CTF 2015 - Facesec Writeup"
date: 2015-04-06 01:56:25 +0430
comments: true
categories: ctf ndh2k15 web symlink
---

**NDH 2015 Facesec Writeup**  
**Point = 100**  
**Category = Web**  
**Description : **  

> "Hello there,

>We are looking for a developer or security consultant to secure our filebox system. We stumbled upon your LinkedIn profile and it seems like you would be a perfect candidate for this job. Could you please send us your CV and Motivation letter?  
Thanks,



>http://facesec.challs.nuitduhack.com/


after you open the link , you can see a login/register system.so sign up and login to my account

after that you seen a upload form with this description :

>You can upload a .txt file if you specify the type of the content (cv or motivation letter).
If you want, you can upload a tar archive which contains two files (cv.txt and motiv.txt).
The content will be update in your profil we can examine your instance.

so try to upload your file , contents of 2 texts go to 2 field in your profile name as CV and Motivation Letter
<!--more-->
if you try to upload file with extension you got an error

you can .tar file.  
according to this link you can execute command with tar file :

[Tar file command execution](http://www.defensecode.com/public/DefenseCode_Unix_WildCards_Gone_Wild.txt)  
so we try to Symlink /etc/passwd to CV.txt

when upload complete and we go to the profile link we can see this : 

    root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/bin/sh bin:x:2:2:bin:/bin:/bin/sh sys:x:3:3:sys:/dev:/bin/sh sync:x:4:65534:sync:/bin:/bin/sync games:x:5:60:games:/usr/games:/bin/sh man:x:6:12:man:/var/cache/man:/bin/sh lp:x:7:7:lp:/var/spool/lpd:/bin/sh mail:x:8:8:mail:/var/mail:/bin/sh news:x:9:9:news:/var/spool/news:/bin/sh uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh proxy:x:13:13:proxy:/bin:/bin/sh www-data:x:33:33:www-data:/var/www:/bin/sh backup:x:34:34:backup:/var/backups:/bin/sh list:x:38:38:Mailing List Manager:/var/list:/bin/sh irc:x:39:39:ircd:/var/run/ircd:/bin/sh gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh nobody:x:65534:65534:nobody:/nonexistent:/bin/sh libuuid:x:100:101::/var/lib/libuuid:/bin/sh sshd:x:101:65534::/var/run/sshd:/usr/sbin/nologin facesec:x:1000:1000:W00tSymL1nkAttackStillW0rksIn2k15:/home/facesec:/bin/sh 
    
Bingo :D  
    
Flag is : W00tSymL1nkAttackStillW0rksIn2k15

WriteUp By Fr0nk
