---
layout: post
title: "NDH CTF 2015 - Updator Writeup"
date: 2015-04-05 03:28:56 +0430
comments: false
categories: ctf exploit crypto web
---

**NDH 2015 Updator Writeup**  
**Point = 200**  
**Category = Exploit**  

> Unhackable : "Not hackable; that cannot be hacked or broken into."
> We manage updates and thus have fixes, this is not a PS3 as it is unhackable ... or is it?
> Score     200
> Link      http://updator.challs.nuitduhack.com/

openning the url gives us a login page and a update button. pressing update button shows an notification:
> The update managing system is still under construction but will be available soon. 

We noticed it's a python script `update.py`. So attempting to loading `update.pyc` gave us the permission to download the file. Instantly i tried to decompile the code with `uncompyle2` as:
<!--more-->
```
$ /usr/local/bin/uncompyle2 update.pyc > update.py
$ cat update.py
# 2015.04.05 03:00:11 IRDT
# Embedded file name: update.py
import config
import sys
KEY = config.KEY

def xor(*args):
    if len(args) < 2:
        sys.exit(0)
    length = len(args[0])
    for arg in args:
        if len(arg) != length:
            sys.exit(0)
        length = len(arg)

    cipher = args[0]
    for arg in args[1:]:
        cipher = ''.join([ chr(ord(arg[i]) ^ ord(cipher[i])) for i in range(len(arg)) ])

    return cipher


class Crypto:

    @staticmethod
    def encrypt(file):
        with open(file, 'r') as fd:
            content = fd.read()
        content = content.ljust(len(content) + (8 - len(content) % 8), '0')
        blocks = [ content[i * 8:(i + 1) * 8] for i in range(len(content) / 8) ]
        with open('%s.encrypted' % file, 'w') as fd:
            encrypted = []
            for i in range(len(blocks)):
                if i == 0:
                    encrypted.append(xor(KEY, blocks[i]))
                else:
                    encrypted.append(xor(KEY, blocks[i], encrypted[i - 1]))

            fd.write(''.join(encrypted))

    @staticmethod
    def decrypt(file):
        with open(file, 'r') as fd:
            content = fd.read()
        blocks = [ content[i * 8:(i + 1) * 8] for i in range(len(content) / 8) ]
        with open('.'.join(file.split('.')[:-1]), 'w') as fd:
            plain = []
            for i in range(len(blocks)):
                if i == 0:
                    plain.append(xor(KEY, blocks[i]))
                else:
                    plain.append(xor(KEY, blocks[i], blocks[i - 1]))

            fd.write(''.join(plain).rstrip('0'))


print 'Content-Type: text/html'
print '\n<!DOCTYPE html>\n<html>\n  <head>\n    <meta charset="UTF-8">\n    <title>Updator - Update system</title>\n    <link rel="stylesheet" href="static/font-awesome/css/font-awesome.css">\n    <link rel="stylesheet" href="static/css/style.css">\n  </head>\n  <body>\n    <div id="info">\n      The update managing system is still under construction but will be available soon.\n    </div>\n  </body>\n</html>\n'
# okay decompyling update.pyc 
# decompiled 1 files: 1 okay, 0 failed, 0 verify failed
# 2015.04.05 03:00:11 IRDT
```

This a simple CBC mode XOR encryption. In the meantime my friend figured out that `robots.txt` tells us we should take look at `/temp/` directory. there was a file named `log.py.encrypted`:

>Index of /temp
>[ICO]	Name	Last modified	Size	Description  
>[DIR]	Parent Directory	 	-   
>[TXT]	log.py.encrypted	31-Mar-2015 17:35 	328 	   
>Apache/2.2.22 (Debian) Server at 10.0.0.5 Port 80

As we saw in the decompiled source the encrypt function encrypts a file and saves as `name+.encrypted`. So we tried to decrypt the file as my friend did. with this assumption that the first block has `import` keyword he xor the first block with that and take a some chars for the `KEY`. remember the CBC mode:
<img src="http://upload.wikimedia.org/wikipedia/commons/8/80/CBC_encryption.svg"/>  
We have second block if we calculate `encrypted[0] ^ encrypted[1]`. So he xored the calculated block and the key he take from the previous part. and there was `atetime`. So after completing the key we can decrypt the file. ( ofcourse it is not a proper solution as you can use xortool and ... but faster than everything :) thanks to him ;) ). So i managed to decrypt the file using edited above source: 

```
import sys
KEY = '6[@dq"&s'

def xor(*args):
    if len(args) < 2:
        sys.exit(0)
    length = len(args[0])
    for arg in args:
        if len(arg) != length:
            sys.exit(0)
        length = len(arg)

    cipher = args[0]
    for arg in args[1:]:
        cipher = ''.join([ chr(ord(arg[i]) ^ ord(cipher[i])) for i in range(len(arg)) ])

    return cipher


def decrypt(file):
    with open(file, 'rb') as fd:
        content = fd.read()
    blocks = [ content[i * 8:(i + 1) * 8] for i in range(len(content) / 8) ]
    with open('.'.join(file.split('.')[:-1]), 'w') as fd:
        plain = []
        for i in range(len(blocks)):
            if i == 0:
                plain.append(xor(KEY, blocks[i]))
            else:
                plain.append(xor(KEY, blocks[i], blocks[i - 1]))

        fd.write(''.join(plain).rstrip('0'))


decrypt('log.py.encrypted')

```

make sure you use `rb` to decrypt properly. We have decrypted file as: 

```
import datetime

LOG_DIR = 'logs'

class Logger():

    @staticmethod
    def log(username, password):
        basename = '%s/%s_%s' % (LOG_DIR, str(datetime.date.today()), username)
        with open(basename, 'a+') as fd:
            fd.write('[%s] Login with password %s\n' % (str(datetime.datetime.today()), password))

```

there is another directory we should take a look `logs` no permission:

> Forbidden  
> You don't have permission to access /logs/ on this server.  
> Apache/2.2.22 (Debian) Server at 10.0.0.5 Port 80

but reading carefully the code gave me the idea to find the exact location:

```python
>>> import datetime
>>> str(datetime.date.today())
'2015-04-04'
>>> print "%s/%s_%s" %("logs", str(datetime.date.today()), "admin")
logs/2015-04-04_admin
>>> 
```

opening `http://updator.challs.nuitduhack.com/logs/2015-04-04_admin` gave me this log:

> [2015-04-04 18:49:48.839448] Login with password Mpt2P4sse2Ouf
> [2015-04-04 18:49:54.044382] Login with password Mot2P4sse2Ouf

Second password worked for me and after logging in we have the flag:

> Well played, here is your flag : zEpbiUFt5p7m84cxOxN6

Interesting challenge So we've got 200pts.

HAMIDx9
