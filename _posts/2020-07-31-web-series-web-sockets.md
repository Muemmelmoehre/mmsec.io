---
layout: single
title: "Web series : Web Sockets"
author_profile: true
categories:
  - web
classes:
tags:
  - web
  - web sockets
---


# Web Sockets

***N.b.:*** *This post is part of my series on web security, heavily inspired by [PortSwigger's Web Security Academy](https://portswigger.net/web-security){:target="_blank"}. They have amazing content and I don't want to simply replicate their work - my goal here is to provide a quick reference, mostly for myself, for those moments when I need to brush up on common web attacks really quick. Enjoy!*

### WHAT
__Web socket :__
* bidirectional protocol, long-lived, allows asynchronous communications
* requires handshake (established over HTTP)
* `wss` protocol uses TLS, `ws` protocol unencrypted communication
* data usually transmitted as JSON

Web sockets can be vulnerable to any attack that works for regular HTTP!

### WHY
We're attacking the transport mechanism and all the input that is getting transmitted is user controlled - so in terms of attacks, (almost) anything goes.


### HOW
* __Intercept web socket messages :__ modify, replay, forge new ones
* __Manipulate handshake :__ Cross-Site Web Socket Hijacking


### Look out for :
Client-side :
* client-side JavaScript, e.g. `var ws = new WebSocket("wss://normal-website.com/chat");`[2]
* `Sec-WebSocket-Version: 13` header
* `Sec-WebSocket-Key: some_b64_here` header
* `Upgrade: websocket` header
* real-time communications, e.g. chats

Server-side :
* `101 Switching Protocols` response
* `Upgrade: websocket` header
* `Sec-WebSocket-Accept: some_b64_here` header


### Resources
[1] [https://portswigger.net/web-security/websockets](https://portswigger.net/web-security/websockets){:target="_blank"}, last visited : 2020-07-31.  
[2] [https://portswigger.net/web-security/websockets/what-are-websockets](https://portswigger.net/web-security/websockets/what-are-websockets){:target="_blank"}, last visited : 2020-07-31.  
[3] [https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking){:target="_blank"}, last visited : 2020-07-31.

-------

# Lab notes for PortSwigger's Web Security Academy labs
## [Manipulating WebSocket messages to exploit vulnerabilities](https://portswigger.net/web-security/websockets/lab-manipulating-messages-to-exploit-vulnerabilities){:target="_blank"}
1. Open live chat and send a message.
2. Open burp. Send a new message and intercept it.
3. Replace the message `{"message":"some_message"}` with `{"message":"<img src=1 onerror='alert(1)'>"}`.
4. Forward the modified web socket message and observe the XSS.
