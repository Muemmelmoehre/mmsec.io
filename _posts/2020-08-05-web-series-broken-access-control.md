---
layout: single
title: "Web series : Broken Access Control"
author_profile: true
categories:
  - web
classes:
tags:
  - web
  - broken access control
  - access control
  - authorization
---


# Broken Access Control

***N.b.:*** *This post is part of my series on web security, heavily inspired by [PortSwigger's Web Security Academy](https://portswigger.net/web-security){:target="_blank"}. They have amazing content and I don't want to simply replicate their work - my goal here is to provide a quick reference, mostly for myself, for those moments when I need to brush up on common web attacks really quick. Enjoy!*

### WHAT
__Access control :__ validating that a user actually has the right to access the resource they requested or to do what they try to; validation based on :
* [__authentication :__](https://mmsec.io/web/web-series-authentication){:target="_blank"} confirm identity
* __session control :__ validate that all following request come from the same user (= same session)

Different types of access controls :
* __Vertical :__ low vs. high privilege users (and everything in between)
* __Horizontal :__ user A vs. user B with the same level of privileges, but access to different subsets of data / functionalities
* __Context-dependent :__ access determined by application state and / or sequence of actions

__Broken Access Control :__ Something, somewhere, went terribly wrong and we're able to get access to something we shouldn't have.


### WHY
Depending on what they can access, an attacker can abuse broken access controls to fully control another user's account and its data, the whole application and potentially the application server. The compromised application may serve us as pivoting point into the internal network and becomes therefore our stepping stone for subsequent attacks.


### HOW
* change parameters
* spider for "hidden" URLs
* information disclosure in server response
* [IDOR](https://mmsec.io/web/web-series-idor/){:target="_blank"}


### Look out for :
* leaking data in server responses
* user-controlled parameters
* unprotected functionalities
* modifyable JSON structures
* non-standard HTTP headers, e.g. `X-Original-URL`, `X-Rewrite-URL`


### Resources
[1] [https://portswigger.net/web-security/access-control](https://portswigger.net/web-security/access-control){:target="_blank"}, last visited : 2020-08-04.  
[2] [https://portswigger.net/web-security/access-control/security-models](https://portswigger.net/web-security/access-control/security-models){:target="_blank"}, last visited : 2020-08-01.

-------

# Lab notes for PortSwigger's Web Security Academy labs
## [Unprotected admin functionality](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality){:target="_blank"}
1. Open burp and access the lab (intercept off).
2. Consult burp's site map and discover `administrator-panel`.
3. Access the admin panel and delete `carlos`.

## [Unprotected admin functionality with unpredictable URL](https://portswigger.net/web-security/access-control/lab-unprotected-admin-functionality-with-unpredictable-url){:target="_blank"}
1. Open burp and access the lab (intercept off).
2. Consult burp's site map and discover `admin-ej7gdu`.
3. Access the admin panel and delete `carlos`.

## [User role controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-role-controlled-by-request-parameter){:target="_blank"}
1. Open burp and access the lab (intercept off).
2. Log in as `wiener`.
3. Access burp's HTTP history and find a request after successful login, i.e. that has the `Admin=false` parameter. Send it to Repeater.
4. Change the parameter to `Admin=true` and resend the request. Show response in browser.
5. Access the admin panel in the menu (intercept on). Intercept the request and change the parameter value again.
6. Forward the request and delete `carlos`.

## [User role can be modified in user profile](https://portswigger.net/web-security/access-control/lab-user-role-can-be-modified-in-user-profile){:target="_blank"}
1. Open burp and access the lab (intercept off).
2. Log in as `wiener` and go to My account.
3. Submit a new email address and intercept the request. Send the POST to Repeater and send. Observe `"roleid":1` in the answer.
5. Add `"roleid":2` into the JSON structure (comma after email!). Resend.
5. Access the admin panel and delete `carlos`.

## [User ID controlled by request parameter](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter){:target="_blank"}
1. Open burp and access the lab (intercept off).
2. Log in as `wiener` and go to My account.
3. Access burp's HTTP history and find a request after successful login, i.e. that has the `id=wiener` parameter. Send it to Repeater.
4. Change the parameter to `id=carlos` and resend the request. Show response in browser and retrieve `carlos`' API key.

## [User ID controlled by request parameter with unpredictable user IDs](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-unpredictable-user-ids){:target="_blank"}
1. Open burp and access the lab (intercept off).
2. Log in as `wiener` and go to My account.
3. Access burp's HTTP history and find a request after successful login, i.e. that has the `id=7fea3240-8d38-4de2-9e69-78f630468e89` parameter. Send it to Repeater.
4. Find a blog post written by `carlos`. Click on his name and intercept the request. Retrieve his GUID from the `userId` parameter.
5. Return to Repeater, plug `carlos`' ID and resend the request. Show response in browser and retrieve `carlos`' API key.

## [User ID controlled by request parameter with data leakage in redirect](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-data-leakage-in-redirect){:target="_blank"}
1. Open burp and access the lab (intercept off).
2. Log in as `wiener` and go to My account. Notice the `id=wiener` parameter.
3. Sent the request to Repeater and modify it to `id=carlos.` Notice `carlos`' API key in the response.

## [User ID controlled by request parameter with password disclosure](https://portswigger.net/web-security/access-control/lab-user-id-controlled-by-request-parameter-with-password-disclosure){:target="_blank"}
1. Open burp and access the lab (intercept off).
2. Log in as `wiener` and go to My account. Notice the `id=wiener` parameter.
3. Sent the request to Repeater and modify it to `id=administrator.` Notice `administrator`'s cleartext password in the response.à
4. Log in as `administrator` and delete `carlos`.

## [Insecure direct object references](https://portswigger.net/web-security/access-control/lab-insecure-direct-object-references){:target="_blank"}
1. Open burp and access the lab (intercept off). Start a live chat.
2. Click on View transcript and intercept the request. Send it to Repeater.
3. Change the file path to `1.txt` and resend. Retrieve `carlos`' cleartext password from the answer. Log in as `carlos`.
