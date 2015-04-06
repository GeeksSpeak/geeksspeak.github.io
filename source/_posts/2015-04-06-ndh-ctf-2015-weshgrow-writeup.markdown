---
layout: post
title: "NDH CTF 2015 - Weshgrow Writeup"
date: 2015-04-06 16:58:41 +0430
comments: true
categories: ctf ndh2k15 crypto hmac hash length-extension-attack
---

**NDH 2015 Weshgrow Writeup**  
**Point = 300**  
**Category = Crypto**  

By openning the url we redirected to following link:

> http://weshgrow.challs.nuitduhack.com/?hmac=ca8473d35a80a5ca4e9f3555c2869f71

As we know HMAC is a cryptographic message for authenticating using a secret key. So this has been made of something. 

Also we could find another HMAC in the page source as you can see: 

> http://weshgrow.challs.nuitduhack.com/admin?hmac=fac0887096a54ac497d968daf4c4fe0b

if you open the /flag address without the purposed HMAC you see redirection to `address+"#missinghmac"`.

So this could be HMAC of pages and we should prepare a HMAC for `flag`.

<!--more-->

By going further into login page, we noticed after submiting the form, HMAC of the password sent to the page not the password itself. it used BHE class in `bhe.js` as mentioned "Best Hash Ever". 

```
var BestHashEver = function() {
    this.state = [
        str2bigInt('1336226589', 10),
        str2bigInt('251977347', 10),
        str2bigInt('716107527', 10),
        str2bigInt('1774966033', 10),
    ];
};
BestHashEver.prototype.bhe_round = function(byte) {
    var c = str2bigInt('162888806', 10);
    console.log(c);
    for (var i=3; i>0; i--) {
        this.state[i] = mod(add(mult(this.state[0], this.state[i]), mult(this.state[0], int2bigInt(byte, 10))), str2bigInt('4294967295', 10));
        console.log(this.state[i]);
    }
    this.state[0] = mod(add(mult(this.state[0], c), mult(this.state[1], int2bigInt(byte, 10))), str2bigInt('4294967295', 10));
};
BestHashEver.prototype.dword2hex = function(dw) {
    var hexchars = ["0", "1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"];
    var output = '';
    var c1 = '', c2=''
    for (var i = 0; i < 4; i++) {
        byte = dw & 0x0000000F;
        c1 = hexchars[byte];
        dw = (dw >> 4);
        byte = dw & 0x0000000F;
        c2 = hexchars[byte];
        dw = (dw >> 4);
        output = output + c2 + c1;
    }
    console.log(output);
    return output;
};
BestHashEver.prototype.hash = function(data) {
    for (var i = 0; i < data.length; i++){
        this.bhe_round(data.charCodeAt(i));
        console.log(this.state);
    }
    /* Generate output. */
    var digest = [
        parseInt(bigInt2str(this.state[0], 10)),
        parseInt(bigInt2str(this.state[1], 10)),
        parseInt(bigInt2str(this.state[2], 10)),
        parseInt(bigInt2str(this.state[3], 10)),
    ];
    return this.dword2hex(digest[0]) + this.dword2hex(digest[1]) + this.dword2hex(digest[2]) +
    this.dword2hex(digest[3]);
};
function hmac(data) {
    _bhe = new BestHashEver();
    return _bhe.hash(data);
}

```
The Hash like md5 has four state variables and multiple rounds which in each round based on previous values and variables, formulas generate a new state variables and change them. Also it has four initialize state value as default.

In this Algorithm each round is for every character of inputs which at the end output produced by hex and concatenation of final state variable.

But there are some flaw in the algorithm such as not using length of input and ...  

This means if we know the state variable value for some string `s`, we can continue the rounds and produce the output of `s+x` for any `x`. this attack mentioned as `hash length extension attack`.

It's obvious that we can obtain state variable' value from HASH(s). The reader should notice that in the `bhe.js` **Big Endian byte order** has been used.

So we have: 

```
Hash(s+x, default initialize state value) = Hash(s, state value of hash(s))
```

based on what discussed earlier and some knowledge about HMAC our scenario is:

```
HMAC(message)= Hash(secret + message)
```
which page name will be used as `message`. As you saw we have valid HMAC for empty(NULL) page name, so:

```
HMAC("") = Hash(secret)

HMAC("flag") = Hash(s, state value of HMAC(""))

```

In order to obtain the proper HMAC i wrote a python script but it can be done by changing default value in js too.


```
def convert2be(s):#convert to big endian byte order
    return s[6:8]+s[4:6]+s[2:4]+s[0:2]
    
def myhex(s):
    return convert2be(hex(s)[2:-1].rjust(8,'0'))
    
def hash(inp,state=[1336226589,251977347,716107527,1774966033]):
    a,b,c,d=state[0],state[1],state[2],state[3]
    m=4294967295
    for x in inp:
        x=ord(x)
        aa=(a*(162888806+x*(b+x)))%m
        bb=(a*(b+x))%m
        cc=(a*(c+x))%m
        dd=(a*(d+x))%m
        a,b,c,d=aa,bb,cc,dd
    return myhex(a)+myhex(b)+myhex(c)+myhex(d)
    
emptyhmac="ca8473d35a80a5ca4e9f3555c2869f71" #hmac("")

import re
emptystate=map(lambda x:int(convert2be(x),16),re.findall('.'*8,emptyhmac))

print hash("flag",emptystate)

```

by executing the script we have the following HMAC:

```
$ python weshgrow-sol.py                                                                                                                                                                      
3f6933240ae234edddc27544d949238c  
```

by opening the following url we have the flag:

> /flag?hmac=3f6933240ae234edddc27544d949238c

> FLAG ? FLAG !
> Can_I_haz_s3cureD_hm4c_plz?

PS: There is a solution as PDF file for `Persian` Users too which can be obtained from [here](/files/ctf/ndh2k15/weshgrow/weshgrow-sol-fa.pdf).

by `f02`

