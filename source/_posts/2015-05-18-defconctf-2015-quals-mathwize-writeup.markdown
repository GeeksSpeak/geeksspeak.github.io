---
layout: post
title: "DefConCTF 2015 Quals - mathwize Writeup"
date: 2015-05-18 14:00:56 +0430
comments: true
categories: coding ppc math
---

**DefConCTF 2015 Mathwize Writeup**  
**Point = 1**  
**Category = Coding**  

We just given the dest address.
> mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me:21249

```
nc mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me 21249
1 + 1 =

```

It's seems we should just answer all the questions.

but among using a script to answer all, i see following patterns:  

  1. using [ and ]  instead of (, )  
  2. using { , } instead of (, )  
  3. using ONE, TWO, THREE, instead of 1, 2, 3  


So here is my completely dirty solution :) :

```
import socket


s = socket.create_connection(("mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me", 21249))


while True:
    a = s.recv(1024)
    print a
    b = eval(a.replace("=", "").replace("{", "(").replace("}", ")").replace("ONE", "1").replace("TWO", "2").replace("THREE", "3").replace("^", "**").replace("[", "(").replace("]", ")"))
    print b
    s.send(str(b)+"\n")

```


And finally:

```
$ python mathwize-sol.py
[..]

You won!!!
The flag is: Farva says you are a FickenChucker and you'd better watch Super Troopers 2
```

another 1 point ;)

@HAMIDx9
