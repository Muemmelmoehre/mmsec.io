---
layout: single
title: "Web series : Insecure Deserialization"
author_profile: true
categories:
  - web
classes: wide
tags:
  - web
  - portswigger
---

# Insecure Deserialization

***N.b.:*** *This post is part of my series on web security, heavily inspired by [PortSwigger's Web Security Academy](https://portswigger.net/web-security){:target="_blank"}. They have amazing content and I don't want to simply replicate their work - my goal here is to provide a quick reference, mostly for myself, for those moments when I need to brush up on common web attacks really quick. Enjoy!*

### WHAT
* __Serialization__ : breaking down a complex data structure into a byte stream
* __Deserialization__ : reconstructing a complex data structure from a byte stream

Whenever an attacker can control the input that is getting deserialized, we have insecure deserialization!

### WHY
Usually, no checks or controls happen during deserialization. Therefore, any data that the attacker introduces into the byte stream will be deserialized - meaning that the attacker can inject whatever data or code he/she pleases.

### HOW
* __Modify the byte stream directly.__ Usually, we first need to url-decode and base64-decode the byte stream to make the underlying structure visible. After modifying the structure, we need to re-encode it to get back a valid byte stream (format must be valid, corrupted data doesn't get deserialized).   
* __Create a valid data structure, modify it to our liking and serialize it ourselves.__


### Look out for :
__PHP :__
* serialized php, e .g. `{O:4:"User":2:{s:4:"name":s:6:"carlos"; s:10:"isLoggedIn":b:1;}`[2]
* `serialize()`
* `unserialize()`

__Java :__
* serialized java, e.g. `ac ed` (hex) `rO0` (b64)[2]
* `java.io.Serializable` interface
* `readObject()` : deserialize data from `InputStream`

__Magic methods :__  
These are special methods that are getting invoked automatically under specific circumstances. They're often triggered during deserialization and we can abuse this functionality to propulse our code from our poisoned serialized object into the website's code. Good jump point for exploits with gadget chains.

__PHAR deserialization :__  
The `phar://` stream interface for PHP Archive files (`.phar`) implicitly performs deserialization.


### Resources
[1] [](https://portswigger.net/web-security/deserialization){:target="_blank"}, last  visited : 2020-07-28.  
[2] [](https://portswigger.net/web-security/deserialization/exploiting){:target="_blank"}, last visited : 2020-07-28.

-------

# Labs
## [Modifying serialized objects](https://portswigger.net/web-security/deserialization/exploiting/lab-deserialization-modifying-serialized-objects){:target="_blank"}

1. Open burp and log in as `wiener`. Intercept the request.
2. Send the session cookie to Decoder. Url decode, then b64 decode.
3. Change the admin value to `b:1`.
4. B64 encode, then url encode. Copy the cookie string.
5. Paste the forged session cookie into every subsequent request in order to act as admin.
